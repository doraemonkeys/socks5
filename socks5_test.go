package socks5

import (
	"bytes"
	"net"
	"reflect"
	"testing"
)

func TestAuth(t *testing.T) {
	server := SOCKS5Server{
		Config: &Config{
			AuthMethod: MethodNoAuth,
		},
	}

	t.Run("a valid client auth message", func(t *testing.T) {
		var buf bytes.Buffer
		buf.Write([]byte{SOCKS5Version, 2, MethodNoAuth, MethodGSSAPI})
		if err := server.auth(&buf); err != nil {
			t.Fatalf("should get error nil but got %s", err)
		}

		want := []byte{SOCKS5Version, MethodNoAuth}
		got := buf.Bytes()
		if !reflect.DeepEqual(want, got) {
			t.Fatalf("should get message %v but got %v", want, got)
		}
	})

	t.Run("an invalid client auth message", func(t *testing.T) {
		var buf bytes.Buffer
		buf.Write([]byte{SOCKS5Version, 2, MethodNoAuth})
		if err := server.auth(&buf); err == nil {
			t.Fatalf("should get error EOF but got nil")
		}
	})
}

func TestWriteRequestSuccessMessage(t *testing.T) {
	var buf bytes.Buffer
	ip := net.IP([]byte{123, 123, 11, 11})

	err := WriteRequestSuccessMessage(&buf, ip, 0x0439)
	if err != nil {
		t.Fatalf("error while writing: %s", err)
	}

	want := []byte{SOCKS5Version, ReplySuccess, ReservedField, TypeIPv4, 123, 123, 11, 11, 0x04, 0x39}
	got := buf.Bytes()
	if !reflect.DeepEqual(want, got) {
		t.Fatalf("message not match: want %v, got %v", want, got)
	}
}
