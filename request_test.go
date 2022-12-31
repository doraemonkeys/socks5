package socks5

import (
	"bytes"
	"testing"
)

func TestNewClientRequestMessage(t *testing.T) {
	tests := []struct {
		Version  byte
		Cmd      Command
		AddrType AddressType
		Address  []byte
		Port     []byte
		Error    error
		Message  ClientRequestMessage
	}{
		{
			Version:  SOCKS5Version,
			Cmd:      CmdConnect,
			AddrType: TypeIPv4,
			Address:  []byte{123, 35, 13, 89},
			Port:     []byte{0x00, 0x50},
			Error:    nil,
			Message: ClientRequestMessage{
				Cmd:      CmdConnect,
				AddrType: TypeIPv4,
				TargetIP: "123.35.13.89",
				Port:     0x0050,
			},
		},
		{
			Version:  0x00,
			Cmd:      CmdConnect,
			AddrType: TypeIPv4,
			Address:  []byte{123, 35, 13, 89},
			Port:     []byte{0x00, 0x50},
			Error:    ErrVersionNotSupported,
			Message: ClientRequestMessage{
				Cmd:      CmdConnect,
				AddrType: TypeIPv4,
				TargetIP: "123.35.13.89",
				Port:     0x0050,
			},
		},
	}

	for _, test := range tests {
		var buf bytes.Buffer
		buf.Write([]byte{test.Version, test.Cmd, ReservedField, test.AddrType})
		buf.Write(test.Address)
		buf.Write(test.Port)

		message, err := NewClientRequestMessage(&buf)
		if err != test.Error {
			t.Fatalf("should get error %s, but got %s\n", test.Error, err)
		}
		if err != nil {
			return
		}

		if *message != test.Message {
			t.Fatalf("should get message %v, but got %v\n", test.Message, *message)
		}
	}
}
