package socks5

import (
	"fmt"
	"io"
	"log"
	"net"
)

const (
	IPv4Length = 4
	IPv6Length = 16
	PortLength = 2
)

type ClientRequestMessage struct {
	Cmd      Command
	AddrType AddressType
	TargetIP string
	Port     uint16
}

type Command = byte

const (
	CmdConnect Command = 0x01
	CmdBind    Command = 0x02
	CmdUDP     Command = 0x03
)

type AddressType = byte

const (
	TypeIPv4   AddressType = 0x01
	TypeDomain AddressType = 0x03
	TypeIPv6   AddressType = 0x04
)

type ReplyType = byte

const (
	ReplySuccess ReplyType = iota
	ReplyServerFailure
	ReplyConnectionNotAllowed
	ReplyNetworkUnreachable
	ReplyHostUnreachable
	ReplyConnectionRefused
	ReplyTTLExpired
	ReplyCommandNotSupported
	ReplyAddressTypeNotSupported
)

func NewClientRequestMessage(conn io.Reader) (*ClientRequestMessage, error) {
	// +----+-----+-------+------+----------+----------+
	// |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
	// +----+-----+-------+------+----------+----------+
	// | 1  |  1  | X'00' |  1   | Variable |    2     |
	// +----+-----+-------+------+----------+----------+
	// VER 版本号，socks5的值为0x05
	// CMD 0x01表示CONNECT请求
	//     0x02表示BIND请求(详情见RFC1928)
	//     0x03表示UDP转发
	// RSV 保留字段，值为0x00
	// ATYP 目标地址类型，DST.ADDR的数据对应这个字段的类型。
	//   0x01表示IPv4地址，DST.ADDR为4个字节
	//   0x03表示域名，DST.ADDR是一个可变长度的域名
	//   0x04表示IPv6地址，DST.ADDR为16个字节
	// DST.ADDR 一个可变长度的值
	// DST.PORT 目标端口，固定2个字节

	// Read version, command, reserved, address type
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		log.Println("read request message error", err)
		return nil, err
	}
	version, command, reserved, addrType := buf[0], buf[1], buf[2], buf[3]

	// Check if the fields are valid
	if version != SOCKS5Version {
		log.Println(ErrVersionNotSupported, version)
		return nil, ErrVersionNotSupported
	}
	if command != CmdConnect && command != CmdBind && command != CmdUDP {
		log.Println(ErrCommandNotSupported, command)
		return nil, ErrCommandNotSupported
	}
	if reserved != ReservedField {
		log.Println(ErrInvalidReservedField, reserved)
		return nil, ErrInvalidReservedField
	}
	if addrType != TypeIPv4 && addrType != TypeIPv6 && addrType != TypeDomain {
		log.Println(ErrAddressTypeNotSupported, addrType)
		return nil, ErrAddressTypeNotSupported
	}

	// Read address and port
	message := ClientRequestMessage{
		Cmd:      command,
		AddrType: addrType,
	}
	switch addrType {
	case TypeIPv6:
		buf = make([]byte, IPv6Length)
		fallthrough
	case TypeIPv4:
		if _, err := io.ReadFull(conn, buf); err != nil {
			log.Println("read request message IP error", err)
			return nil, err
		}
		ip := net.IP(buf)
		message.TargetIP = ip.String()
	case TypeDomain:
		if _, err := io.ReadFull(conn, buf[:1]); err != nil {
			log.Println("read request message domain length error", err)
			return nil, err
		}
		domainLength := buf[0]
		if domainLength > IPv4Length {
			buf = make([]byte, domainLength)
		}
		if _, err := io.ReadFull(conn, buf[:domainLength]); err != nil {
			log.Println("read request message domain error", err)
			return nil, err
		}
		message.TargetIP = string(buf[:domainLength])
	}
	fmt.Println("message.Address", message.TargetIP)

	// Read port number
	if _, err := io.ReadFull(conn, buf[:PortLength]); err != nil {
		return nil, err
	}
	message.Port = (uint16(buf[0]) << 8) + uint16(buf[1])
	fmt.Println("message.Port", message.Port)
	return &message, nil
}

func WriteRequestSuccessMessage(conn io.Writer, ip net.IP, port uint16) error {
	// +----+-----+-------+------+----------+----------+
	// |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
	// +----+-----+-------+------+----------+----------+
	// | 1  |  1  | X'00' |  1   | Variable |    2     |
	// +----+-----+-------+------+----------+----------+
	// VER socks版本，这里为0x05
	// REP Relay field,内容取值如下 X’00’ succeeded
	// RSV 保留字段
	// ATYPE 地址类型
	// BND.ADDR 服务绑定的地址
	// BND.PORT 服务绑定的端口DST.PORT

	addressType := TypeIPv4
	if len(ip) > IPv4Length {
		if len(ip) != IPv6Length {
			log.Println("invalid IP length:", len(ip), ",ip:", ip)
		}
		addressType = TypeIPv6
	}

	// Write version, reply success, reserved, address type
	_, err := conn.Write([]byte{SOCKS5Version, ReplySuccess, ReservedField, addressType})
	if err != nil {
		log.Println("write request success message error:", err)
		return err
	}

	// Write bind IP(IPv4/IPv6)
	if _, err := conn.Write(ip); err != nil {
		log.Println("write request success message error:", err)
		return err
	}

	// Write bind port
	buf := make([]byte, 2)
	buf[0] = byte(port >> 8)
	buf[1] = byte(port - uint16(buf[0])<<8)
	_, err = conn.Write(buf)
	if err != nil {
		log.Println("write request success message error:", err)
	}
	return err
}

func WriteRequestFailureMessage(conn io.Writer, replyType ReplyType) error {
	_, err := conn.Write([]byte{SOCKS5Version, replyType, ReservedField, TypeIPv4, 0, 0, 0, 0, 0, 0})
	if err != nil {
		log.Println("write request failure message error", err)
	}
	return err
}
