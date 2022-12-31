package socks5

import (
	"errors"
	"io"
	"log"
)

type ClientAuthMessage struct {
	Version  byte
	NMethods byte
	Methods  []Method
}

type ClientPasswordMessage struct {
	Username string
	Password string
}

type Method = byte

const (
	MethodNoAuth Method = 0x00
	MethodGSSAPI Method = 0x01
	// Since the request carries the  password in cleartext,
	// this subnegotiation is not recommended for environments where "sniffing" is possible and practical.
	MethodPassword     Method = 0x02
	MethodNoAcceptable Method = 0xff
)

const (
	PasswordMethodVersion = 0x01
	PasswordAuthSuccess   = 0x00
	PasswordAuthFailure   = 0x01
)

var (
	ErrPasswordCheckerNotSet = errors.New("error password checker not set")
	ErrPasswordAuthFailure   = errors.New("error authenticating username/password")
)

func NewClientAuthMessage(conn io.Reader) (*ClientAuthMessage, error) {
	// +----+----------+----------+
	// |VER | NMETHODS | METHODS  |
	// +----+----------+----------+
	// | 1  |    1     | 1 to 255 |
	// +----+----------+----------+
	// VER: 协议版本，socks5为0x05
	// NMETHODS: 支持认证的方法数量
	// METHODS: 对应NMETHODS，NMETHODS的值为多少，METHODS就有多少个字节。RFC预定义了一些值的含义，内容如下:
	// X’00’ NO AUTHENTICATION REQUIRED
	// X’02’ USERNAME/PASSWORD

	// Read version, nMethods
	buf := make([]byte, 2)
	_, err := io.ReadFull(conn, buf)
	if err != nil {
		log.Println("error reading version and nMethods", err)
		return nil, err
	}

	// Validate version
	if buf[0] != SOCKS5Version {
		log.Println("error version not supported", buf[0])
		return nil, ErrVersionNotSupported
	}

	// Read methods
	nmethods := buf[1]
	buf = make([]byte, nmethods)
	_, err = io.ReadFull(conn, buf)
	if err != nil {
		log.Println("error reading methods", err)
		return nil, err
	}

	return &ClientAuthMessage{
		Version:  SOCKS5Version,
		NMethods: nmethods,
		Methods:  buf,
	}, nil
}

func SendServerAuthMessage(conn io.Writer, method Method) error {
	// +----+--------+
	// |VER | METHOD |
	// +----+--------+
	// | 1  |   1    |
	// +----+--------+
	// If the selected METHOD is 0xFF, none of the methods listed by the client are acceptable,
	// and the client MUST close the connection.
	buf := []byte{SOCKS5Version, method}
	_, err := conn.Write(buf)
	if err != nil {
		log.Println("send server auth message", buf, "error:", err)
	}
	return err
}

func NewClientPasswordMessage(conn io.Reader) (*ClientPasswordMessage, error) {
	// Read version and username length
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		log.Println("error reading version and username length", err)
		return nil, err
	}
	version, usernameLen := buf[0], buf[1]
	if version != PasswordMethodVersion {
		log.Println("error password method version not supported", version)
		return nil, ErrMethodVersionNotSupported
	}

	// Read username, password length
	buf = make([]byte, usernameLen+1)
	if _, err := io.ReadFull(conn, buf); err != nil {
		log.Println("error reading username and password length", err)
		return nil, err
	}
	username, passwordLen := string(buf[:len(buf)-1]), buf[len(buf)-1]

	// Read password
	if len(buf) < int(passwordLen) {
		buf = make([]byte, passwordLen)
	}
	if _, err := io.ReadFull(conn, buf[:passwordLen]); err != nil {
		log.Println("error reading password", err)
		return nil, err
	}

	return &ClientPasswordMessage{
		Username: username,
		Password: string(buf[:passwordLen]),
	}, nil
}

func WriteServerPasswordMessage(conn io.Writer, status byte) error {
	_, err := conn.Write([]byte{PasswordMethodVersion, status})
	return err
}
