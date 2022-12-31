package socks5

import (
	"bytes"
	"log"
	"reflect"
	"testing"
)

func TestNewClientAuthMesssage(t *testing.T) {
	t.Run("should generate a message", func(t *testing.T) {
		b := []byte{SOCKS5Version, 2, MethodNoAuth, MethodGSSAPI}
		r := bytes.NewReader(b)

		message, err := NewClientAuthMessage(r)
		if err != nil {
			t.Fatalf("want error = nil but got %s", err)
		}

		if message.Version != SOCKS5Version {
			t.Fatalf("want socks5version but got %d", message.Version)
		}
		if message.NMethods != 2 {
			t.Fatalf("want nmethods = 2 but got %d", message.NMethods)
		}
		if !reflect.DeepEqual(message.Methods, []byte{MethodNoAuth, MethodGSSAPI}) {
			t.Fatalf("want methods: %v, but got %v", []byte{MethodNoAuth, MethodGSSAPI}, message.Methods)
		}
	})

	t.Run("methods length is shorter than nmethods", func(t *testing.T) {
		b := []byte{SOCKS5Version, 2, MethodNoAuth}
		r := bytes.NewReader(b)

		_, err := NewClientAuthMessage(r)
		if err == nil {
			t.Fatalf("should get error != nil but got nil")
		}
	})
}

func TestNewServerAuthMessage(t *testing.T) {
	t.Run("should send noauth", func(t *testing.T) {
		var buf bytes.Buffer
		err := SendServerAuthMessage(&buf, MethodNoAuth)
		if err != nil {
			t.Fatalf("should get nil error but got %s", err)
		}

		got := buf.Bytes()
		if !reflect.DeepEqual(got, []byte{SOCKS5Version, MethodNoAuth}) {
			t.Fatalf("should send %v, but send %v", []byte{SOCKS5Version, MethodNoAuth}, got)
		}
	})

	t.Run("should send no acceptable", func(t *testing.T) {
		var buf bytes.Buffer
		err := SendServerAuthMessage(&buf, MethodNoAcceptable)
		if err != nil {
			t.Fatalf("should get nil error but got %s", err)
		}

		got := buf.Bytes()
		if !reflect.DeepEqual(got, []byte{SOCKS5Version, MethodNoAcceptable}) {
			t.Fatalf("should send %v, but send %v", []byte{SOCKS5Version, MethodNoAcceptable}, got)
		}
	})
}

func TestNewClientPasswordMessage(t *testing.T) {
	t.Run("valid password auth message", func(t *testing.T) {
		username, password := "admin", "123456"
		var buf bytes.Buffer
		buf.Write([]byte{PasswordMethodVersion, 5})
		buf.WriteString(username)
		buf.WriteByte(6)
		buf.WriteString(password)

		message, err := NewClientPasswordMessage(&buf)
		if err != nil {
			log.Fatalf("want error = nil but got %s", err)
		}

		want := ClientPasswordMessage{Password: password, Username: username}
		if *message != want {
			log.Fatalf("want message %#v but got %#v", *message, want)
		}
	})
}
