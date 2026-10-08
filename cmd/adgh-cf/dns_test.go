package main

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

func TestAdGuardDNSUsesConfiguredTCPServer(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(2 * time.Second))
				var size [2]byte
				if _, err := io.ReadFull(conn, size[:]); err != nil {
					return
				}
				q := make([]byte, binary.BigEndian.Uint16(size[:]))
				if _, err := io.ReadFull(conn, q); err != nil || len(q) < 17 {
					return
				}
				end := 12
				for end < len(q) && q[end] != 0 {
					end += 1 + int(q[end])
				}
				end += 5
				if end > len(q) {
					return
				}
				answer := append([]byte{}, q[:end]...)
				binary.BigEndian.PutUint16(answer[2:4], 0x8180)
				binary.BigEndian.PutUint16(answer[6:8], 1)
				binary.BigEndian.PutUint16(answer[8:10], 0)
				binary.BigEndian.PutUint16(answer[10:12], 0)
				answer = append(answer, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 0, 0, 4, 104, 17, 128, 164)
				binary.BigEndian.PutUint16(size[:], uint16(len(answer)))
				conn.Write(size[:])
				conn.Write(answer)
			}()
		}
	}()
	c := Config{Domain: "example.com", AdGuardHomeDNS: listener.Addr().String()}
	ips, err := resolveAdGuard(context.Background(), c)
	if err != nil || len(ips) != 1 || ips[0] != "104.17.128.164" {
		t.Fatal("DNS verification failed", ips, err)
	}
}
