package main

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// flock is released by the kernel even after a crash. Keep the inode in place:
// deleting the lock file would let another process lock a different inode.
func lockOptimizer(path string) (func(), error) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, fmt.Errorf("optimizer already running or lock unavailable: %w", err)
	}
	return func() { syscall.Flock(int(f.Fd()), syscall.LOCK_UN); f.Close() }, nil
}
