package main

import (
	"bytes"
	"os"
	"syscall"
	"unsafe"
)

// openPTY 打开一对伪终端（macOS：/dev/ptmx + grantpt/unlockpt/ptsname 对应的 ioctl）。
func openPTY() (master, slave *os.File, err error) {
	master, err = os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		return nil, nil, err
	}
	fd := master.Fd()
	var name [128]byte
	for _, req := range []struct {
		op  uintptr
		arg uintptr
	}{
		{syscall.TIOCPTYGRANT, 0},
		{syscall.TIOCPTYUNLK, 0},
		{syscall.TIOCPTYGNAME, uintptr(unsafe.Pointer(&name[0]))},
	} {
		if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, fd, req.op, req.arg); e != 0 {
			master.Close()
			return nil, nil, e
		}
	}
	path := string(name[:bytes.IndexByte(name[:], 0)])
	slave, err = os.OpenFile(path, os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		master.Close()
		return nil, nil, err
	}
	return master, slave, nil
}
