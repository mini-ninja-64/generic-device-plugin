// Copyright 2023 the generic-device-plugin authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package deviceplugin

import (
	"crypto/sha1"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"k8s.io/kubelet/pkg/apis/deviceplugin/v1beta1"
)

const (
	usbDevicesDir                = "/sys/bus/usb/devices/"
	usbDevicesDirVendorIDFile    = "idVendor"
	usbDevicesDirProductIDFile   = "idProduct"
	usbDevicesDirProductNameFile = "product"
	usbDevicesDirSerialFile      = "serial"
	usbDevicesDirBusFile         = "busnum"
	usbDevicesDirBusDevFile      = "devnum"
	usbDevBus                    = "/dev/bus/usb/%03x/%03x"
)

type CombinedUSBSpec struct {
	usbSpec    *USBSpec
	usbTtySpec *UsbTtySpec
}

// USBSpec represents a USB device specification that should be discovered.
// A USB device must match exactly on all the present attributes to pass.
type USBSpec struct {
	// Vendor is the USB Vendor ID of the device to match on.
	// (Both of these get mangled to uint16 for processing - but you should use the hexadecimal representation.)
	Vendor USBID `json:"vendor"`
	// Product is the USB Product ID of the device to match on.
	Product USBID `json:"product"`
	// Serial is the serial number of the device to match on.
	Serial string `json:"serial"`
	// ProductName is the usb product name of the device to match on.
	ProductName string `json:"productName"`
}

type UsbTtySpec struct {
	USBSpec

	MountPath string `json:"mountPath"`
}

// USBID is a representation of a platform or vendor ID under the USB standard (see gousb.ID)
type USBID uint16

// UnmarshalJSON handles incoming standard platform / vendor IDs.
func (id *USBID) UnmarshalJSON(data []byte) error {
	strData := string(data)
	if strData == "null" || strData == `""` {
		return nil
	}
	// To be safe, strip out newlines and quotation marks
	strData = strings.ReplaceAll(strData, "\n", "")
	strData = strings.ReplaceAll(strData, "\"", "")

	// then attempt to parse as uint16.
	dAsInt, err := strconv.ParseUint(strData, 16, 16)
	if err != nil {
		return fmt.Errorf("malformed device data %q: %w", strData, err)
	}
	*id = USBID(uint16(dAsInt))
	return nil
}

// String returns a standardised hexadecimal representation of the USBID.
func (id *USBID) String() string {
	return fmt.Sprintf("%04x", int(*id))
}

// ToUSBIDHookFunc handles mapstructure decode of standard platform / vendor IDs.
func ToUSBIDHookFunc(f, t reflect.Type, data interface{}) (interface{}, error) {
	if t != reflect.TypeOf(USBID(0)) {
		return data, nil
	}

	switch f.Kind() {
	case reflect.String:
		return strconv.ParseUint(data.(string), 16, 16)
	default:
		return data, nil
	}
}

// usbDevice represents a physical, tangible USB device.
type usbDevice struct {
	// Vendor is the USB Vendor ID of the device.
	Vendor USBID `json:"vendor"`
	// Product is the USB Product ID of the device.
	Product USBID `json:"product"`
	// Bus is the physical USB bus this device is located at.
	Bus uint16 `json:"bus"`
	// BusDevice is the location of the device on the Bus.
	BusDevice uint16 `json:"busdev"`
	// Serial is the serial number of the device.
	Serial string `json:"serial"`
	// ProductName is the usb product name of the device to match on.
	ProductName string   `json:"productname"`
	Ttys        []string `json:"ttys"`
}

// BusPath returns the platform-correct path to the raw device.
func (dev *usbDevice) BusPath() (path string) {
	return fmt.Sprintf(usbDevBus, dev.Bus, dev.BusDevice)
}

// readFileToUint16 reads the file at the given path, then returns a representation of that file as uint16.
// Ignores newlines.
// Returns an error if the file could not be read, or parsed as uint16.
func readFileToUint16(fsys fs.FS, path string) (out uint16, err error) {
	bytes, err := fs.ReadFile(fsys, path)
	if err != nil {
		// We can't read this file for some reason
		return out, err
	}
	// To be safe, strip out newlines
	dataStr := strings.ReplaceAll(string(bytes), "\n", "")

	// then attempt to parse as uint16.
	dAsInt, err := strconv.ParseUint(dataStr, 16, 16)
	if err != nil {
		return out, fmt.Errorf("malformed device data %q: %w", dataStr, err)
	}
	// Potential for overflowing, but presume we know what we're doing.
	return uint16(dAsInt), nil
}

func resolveSymlink(fsys fs.FS, path string) (string, error) {
	fileInfo, err := fs.Lstat(fsys, path)
	if err != nil {
		return "", err
	}
	if fileInfo.Mode()&fs.ModeSymlink != fs.ModeSymlink {
		return path, nil
	}

	link, err := fs.ReadLink(fsys, path)
	if err != nil {
		return "", err
	}
	return link, nil
}

// TODO: this doesnt actually seem to do what its supposed to?
func resolveSymlinkToDir(fsys fs.FS, path string) (absolutePath string, err error) {
	fileInfo, err := fs.Stat(fsys, path)
	if err != nil {
		return "", err
	}
	if !fileInfo.IsDir() {
		return "", fmt.Errorf("not a directory")
	}
	return path, nil
}

func realpath(fsys fs.FS, path string) (string, error) {
	path, err := resolveSymlink(fsys, path)
	if err != nil {
		return "", err
	}
	path, err = filepath.Abs(path)
	if err != nil {
		return "", err
	}
	return path, nil
}

// queryUSBDeviceCharacteristicsByDirectory scans the given directory for information regarding the given USB device,
// then returns a pointer to a new usbDevice if information is found.
// Safe to presume that result is set if err is nil.
func queryUSBDeviceCharacteristicsByDirectory(fsys fs.FS, path string) (result *usbDevice, err error) {
	// Test if symlink needs to be followed.
	path, err = resolveSymlinkToDir(fsys, path)

	if err != nil {
		return result, err
	}

	// Try to find the vendor ID file inside this device - this is a good indication that we're dealing with a device, not a bus.
	vnd, err := readFileToUint16(fsys, filepath.Join(path, usbDevicesDirVendorIDFile))
	if err != nil {
		// We can't read the vendor file for some reason, it probably doesn't exist.
		return result, err
	}

	prd, err := readFileToUint16(fsys, filepath.Join(path, usbDevicesDirProductIDFile))
	if err != nil {
		return result, err
	}

	serial := ""
	serBytes, err := fs.ReadFile(fsys, filepath.Join(path, usbDevicesDirSerialFile))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return result, err
	}
	if serBytes != nil {
		serial = strings.TrimSuffix(string(serBytes), "\n")
	}

	productName := ""
	productNameBytes, err := fs.ReadFile(fsys, filepath.Join(path, usbDevicesDirProductNameFile))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return result, err
	}
	if productNameBytes != nil {
		productName = strings.TrimSuffix(string(productNameBytes), "\n")
	}

	// The following two calls shouldn't fail if the above two exist and are readable.
	bus, err := readFileToUint16(fsys, filepath.Join(path, usbDevicesDirBusFile))
	if err != nil {
		return result, err
	}
	busLoc, err := readFileToUint16(fsys, filepath.Join(path, usbDevicesDirBusDevFile))
	if err != nil {
		return result, err
	}

	ttys, err := findDevicesForSubsystem(fsys, path, "/sys/class/tty")
	if err != nil {
		return result, err
	}

	res := usbDevice{
		Vendor:      USBID(vnd),
		Product:     USBID(prd),
		Bus:         bus,
		BusDevice:   busLoc,
		Serial:      serial,
		ProductName: productName,
		Ttys:        ttys,
	}
	return &res, nil
}

func findDevicesForSubsystem(fsys fs.FS, startPath string, desiredSubsystem string) ([]string, error) {
	var matchingDevices = make(map[string]struct{})

	err := fs.WalkDir(fsys, startPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Name() != "subsystem" {
			return nil
		}
		resolvedSubsystem, err := realpath(fsys, path)
		if err != nil {
			return err
		}
		if resolvedSubsystem == desiredSubsystem {
			devName := filepath.Base(filepath.Dir(path))
			devPath := filepath.Join("/dev", devName)
			matchingDevices[devPath] = struct{}{}
		}
		return nil
	})
	if err != nil {
		return []string{}, err
	}

	return slices.Collect(maps.Keys(matchingDevices)), nil
}

// enumerateUSBDevices rapidly scans the OS system bus for attached USB devices.
// Pure Go; does not require external linking.
func enumerateUSBDevices(logger log.Logger, fsys fs.FS, dir string) (specs []usbDevice, err error) {
	allDevs, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return []usbDevice{}, err
	}

	// Set up a WaitGroup with a buffered channel for results
	var wg sync.WaitGroup
	devs := make(chan *usbDevice)

	// You could also have a shared slice with a mutex guard, but this way is arguably a little more performant.
	for _, dev := range allDevs {
		// Copy the loop variable
		dev := dev

		// Spawn a goroutine to discover the device information
		wg.Add(1)
		go func() {
			defer wg.Done()
			result, err := queryUSBDeviceCharacteristicsByDirectory(fsys, filepath.Join(dir, dev.Name()))
			if err != nil {
				level.Warn(logger).Log("msg", fmt.Sprintf("failed to query usb devices: %v", err))
				// do we want to handle errors here?
				return
			}
			// Successful data will get thrown onto the buffered channel for later merging
			devs <- result
		}()
	}

	go func() {
		defer close(devs)
		wg.Wait()
	}()

	// Now unwind the buffer into the results array
	for d := range devs {
		specs = append(specs, *d)
	}

	return
}

// searchUSBDevices returns a subset of the "devices" slice containing only those usbDevices that match the given vendor and product arguments.
func searchUSBDevices(devices *[]usbDevice, vendor USBID, product USBID, serial string, productName string) (devs []usbDevice, err error) {
	for _, dev := range *devices {
		if dev.Vendor == vendor &&
			dev.Product == product &&
			(serial == "" || dev.Serial == serial) &&
			(productName == "" || dev.ProductName == productName) {
			devs = append(devs, dev)
		}
	}
	return
}

type pathMount struct {
	host      string
	container string
}

func (gp *GenericPlugin) discoverUSB() (devices []device, err error) {
	usbDevs, err := enumerateUSBDevices(gp.logger, gp.fs, usbDevicesDir)
	for _, usbDev := range usbDevs {
		_ = level.Debug(gp.logger).Log("msg", "discovered USB device", "usbdevice", fmt.Sprintf("%v:%v", usbDev.Vendor.String(), usbDev.Product.String()), "path", usbDev.BusPath())
	}

	for _, group := range gp.ds.Groups {
		var paths []pathMount
		if err != nil {
			_ = level.Warn(gp.logger).Log("msg", fmt.Sprintf("failed to enumerate usb devices: %v", err))
			return devices, nil
		}
		// group.USBSpecs
		var usbSpecs []CombinedUSBSpec
		for _, usbTtySpec := range group.USBTTYSpecs {
			usbSpecs = append(usbSpecs, CombinedUSBSpec{usbTtySpec: usbTtySpec})
		}
		for _, usbSpec := range group.USBSpecs {
			usbSpecs = append(usbSpecs, CombinedUSBSpec{usbSpec: usbSpec})
		}
		for _, spec := range usbSpecs {
			var device *USBSpec
			if spec.usbSpec != nil {
				device = spec.usbSpec
			} else if spec.usbTtySpec != nil {
				device = &spec.usbTtySpec.USBSpec
			}
			matches, err := searchUSBDevices(&usbDevs, device.Vendor, device.Product, device.Serial, device.ProductName)
			if err != nil {
				return nil, err
			}
			if len(matches) == 0 {
				_ = level.Debug(gp.logger).Log("msg", "no USB devices found attached to system")
			}
			for _, match := range matches {
				_ = level.Debug(gp.logger).Log(
					"msg", "USB device match",
					"usbdevice", fmt.Sprintf("%v:%v", device.Vendor.String(), device.Product.String()),
					"path", match.BusPath(),
				)

				ttyCount := 0
				if spec.usbTtySpec != nil {
					if len(match.Ttys) == 0 {
						_ = level.Warn(gp.logger).Log("msg", "USB TTY match was found but it has no TTYs")

					}
					for _, ttyPath := range match.Ttys {
						paths = append(paths, pathMount{
							host:      ttyPath,
							container: spec.usbTtySpec.MountPath + strconv.Itoa(ttyCount),
						})
						ttyCount += 1
					}
				}
				paths = append(paths, pathMount{
					host:      match.BusPath(),
					container: match.BusPath(),
				})
			}
		}
		if len(paths) > 0 {
			for j := uint(0); j < group.Count; j++ {
				h := sha1.New()
				h.Write([]byte(strconv.FormatUint(uint64(j), 10)))
				d := device{
					Device: &v1beta1.Device{
						Health: v1beta1.Healthy,
					},
				}
				for _, path := range paths {
					d.deviceSpecs = append(d.deviceSpecs, &v1beta1.DeviceSpec{
						HostPath:      path.host,
						ContainerPath: path.container,
						Permissions:   "rw",
					})
					h.Write([]byte(path.host))
				}
				d.ID = fmt.Sprintf("%x", h.Sum(nil))
				devices = append(devices, d)
			}
		}
	}
	return devices, nil
}
