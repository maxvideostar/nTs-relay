//go:build linux

package main

import (
	"errors"
	"log"
	"syscall"
)

func defaultConfigPath() string { return "/etc/streamhub/config.json" }

func setUDPSockOpts(fd uintptr, ttl int, setIf bool, ifIP [4]byte) {
	syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_MULTICAST_TTL, ttl)
	syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TTL, ttl)
	syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_SNDBUF, 4<<20)
	if setIf {
		syscall.SetsockoptInet4Addr(int(fd), syscall.IPPROTO_IP, syscall.IP_MULTICAST_IF, ifIP)
	}
}

// procesele ffmpeg/srt-live-transmit mor odată cu StreamHub
func childProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
}

func platformInit()      {}
func openBrowser(string) {}

func platformService(bool, string) error {
	return errors.New("pe Linux folosește install-streamhub.sh (serviciu systemd)")
}

func fatal(err error) { log.Fatal(err) }
