package socks5

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"
)

// A net.Conn wrapper for writeWithDeadline and readWithDeadline methods.
type connection struct {
	net.Conn
}

// A socksConn instance represents a proxy session.
type socksConn struct {
	cC *connection
	sC *connection

	// Is used to access the logger, time limits, etc.
	server *Server

	// Any data can be attached to a session by being returned by Authenticate().
	data interface{}
}

type customError struct {
	currentErr error
	data       interface{}
}

func (e customError) Error() string {
	return fmt.Sprintf("%s%v", e.currentErr, e.data)
}

const (
	socks5Version byte = 0x05

	positionVersion          = 0
	positionNumSupportedAuth = 1
	positionFRAG             = 2
	positionAuthMethod       = 2
	positionCMD              = 1
	positionATYP             = 3
	positionAddress          = 4
	positionULen             = 1
	positionUsername         = 2

	authMethodUPass byte = 0x02
	authMethodNone  byte = 0x00

	cmdConnect      byte = 0x01
	cmdUDPAssociate byte = 0x03

	typeIPv4   byte = 0x01
	typeDomain byte = 0x03
	typeIPv6   byte = 0x04

	authMethodRejected byte = 0xff

	responseSuccess      byte = 0x00
	responseUnknownError byte = 0xff

	uPassHandshakeVersion byte = 0x01
	uPassHandshakeSuccess byte = 0x00

	valueReserved byte = 0x00
)

var (
	errProtocolUnsupported = errors.New("only SOCKS5 protocol supported. proposed protocol: ")
	errCommandUnsupported  = errors.New("only CONNECT and UDP ASSOCIATE commands are supported. requested command: ")
	errAddrBlocked         = errors.New("address not allowed. requested destination: ")
	errInvalidAddress      = errors.New("invalid address")
	errUnknown             = errors.New("unknown error")
	errCorruptedPacket     = errors.New("corrupted packet")
	errNoAuthMethod        = errors.New("no supported auth method found. proposed methods: ")
	errUnauthorized        = errors.New("unauthorized username: ")
)

func (c *socksConn) handshake() (err error) {
	var (
		n int
		b = c.server.bufPoolLarge.Get().([]byte)
	)
	const minLen = 3

	defer c.server.bufPoolLarge.Put(b)
	if n, err = c.cC.readWithDeadline(b, c.server.HandshakeStepTimeLimit); err != nil {
		return err
	}
	if n < minLen {
		return errCorruptedPacket
	}
	if b[positionVersion] != socks5Version {
		return customError{errProtocolUnsupported, b[positionVersion]}
	}
	return c.authenticate(b[:n])
}

func (c *socksConn) authenticate(b []byte) (err error) {
	var methods []byte
	var ok bool
	const minMethods, maxMethods = 1, 255

	defer func() {
		if err != nil {
			c.server.lg.Println(err.Error())
		}
	}()

	if numMethods := int(b[positionNumSupportedAuth]); numMethods > minMethods && numMethods <= maxMethods {
		methods = b[positionAuthMethod : positionAuthMethod+numMethods]
	} else if numMethods == minMethods {
		methods = []byte{b[positionAuthMethod]}
	} else {
		return errCorruptedPacket
	}
	for _, method := range methods {
		switch method {
		case authMethodNone:
			if c.server.AuthMethodNoneAllowed {
				_, err = c.cC.writeWithDeadline([]byte{socks5Version, authMethodNone}, c.server.HandshakeStepTimeLimit)
				return err
			}
		case authMethodUPass:
			if _, err = c.cC.writeWithDeadline([]byte{socks5Version, authMethodUPass}, c.server.HandshakeStepTimeLimit); err != nil {
				return err
			}
			if _, err = c.cC.readWithDeadline(b[:cap(b)], c.server.HandshakeStepTimeLimit); err != nil {
				return err
			}

			u, p, err := validateAuthData(b[:cap(b)])
			if err != nil {
				c.cC.writeWithDeadline([]byte{uPassHandshakeVersion, responseUnknownError}, c.server.HandshakeStepTimeLimit)
				return err
			}
			if ok, c.data = c.server.Authenticate(u, p); !ok {
				_, err = c.cC.writeWithDeadline([]byte{uPassHandshakeVersion, responseUnknownError}, c.server.HandshakeStepTimeLimit)
				return customError{errUnauthorized, u}
			}
			_, err = c.cC.writeWithDeadline([]byte{uPassHandshakeVersion, uPassHandshakeSuccess}, c.server.HandshakeStepTimeLimit)
			return err
		default:
			continue
		}
	}
	c.cC.writeWithDeadline([]byte{socks5Version, authMethodRejected}, c.server.HandshakeStepTimeLimit)
	return customError{errNoAuthMethod, methods}
}

func validateAuthData(b []byte) (username, password string, err error) {
	const uLenShift, pLenShift = 2, 3

	err = errCorruptedPacket
	if b[positionVersion] != uPassHandshakeVersion {
		return
	}

	uLen := int(b[positionULen])
	if int(uLen+uLenShift) > cap(b) || uLen == 0 {
		return
	}

	username = string(b[positionUsername : uLen+uLenShift])
	pLen := int(b[uLen+uLenShift])
	if int(uLen+pLenShift+pLen) > cap(b) || pLen == 0 {
		return
	}
	password = string(b[uLen+pLenShift : uLen+pLenShift+pLen])
	err = nil
	return
}

func (c *socksConn) processRequest() (err error) {
	var (
		n       int
		dst     net.Addr
		dstTCP  *net.TCPAddr
		b       = c.server.bufPoolSmall.Get().([]byte)
		cDialed net.Conn
	)
	const minLen = 7

	defer func() {
		if err != nil {
			c.server.lg.Println(err.Error())
		}
	}()
	defer c.server.bufPoolSmall.Put(b)

	if n, err = c.cC.readWithDeadline(b, c.server.HandshakeStepTimeLimit); err != nil {
		return err
	}
	if n < minLen {
		return errCorruptedPacket
	}
	if b[positionVersion] != socks5Version {
		return customError{errProtocolUnsupported, b[positionVersion]}
	}

	switch b[positionCMD] {
	case cmdConnect:
		if n-2 <= positionAddress {
			return errUnknown
		}
		if dst, _, err = evalDestination("tcp", b[:n]); err != nil {
			return err
		}

		dstTCP = dst.(*net.TCPAddr)
		if !c.server.CheckIP(dstTCP.IP) {
			return customError{errAddrBlocked, dstTCP.IP.String()}
		}

		addr := net.JoinHostPort(dstTCP.IP.String(), strconv.FormatUint(uint64(dstTCP.Port), 10))
		if cDialed, err = net.DialTimeout("tcp", addr, c.server.HandshakeStepTimeLimit); err != nil {
			return err
		}
		if cTCP, ok := cDialed.(*net.TCPConn); ok {
			c.sC = &connection{cTCP}
		} else {
			return errUnknown
		}
		/*
			it is unclear what address to use in response to a CONNECT request
		*/
		response := []byte{socks5Version, responseSuccess, valueReserved}
		response = append(response, b[positionATYP:n]...)
		_, err = c.cC.writeWithDeadline(response, c.server.HandshakeStepTimeLimit)
		if err != nil {
			return err
		}
		go copyAndQuit(c)
		return nil
	case cmdUDPAssociate:
		relayTakeOver(c.cC, c.server)
		return nil
	default:
		return customError{errCommandUnsupported, b[positionCMD]}
	}
}

func evalDestination(network string, data []byte) (dst net.Addr, addrLen int, err error) {
	var a net.IP
	var port []byte
	var nA net.Addr
	const paddingLen, portLen, domainLen = 4, 2, 1
	const domainLenShift, domainShift = 1, 2

	err = errCorruptedPacket
	dst = nA
	switch data[positionATYP] {
	case typeIPv4:
		if len(data) < paddingLen+net.IPv4len+portLen {
			return
		}
		a = net.IPv4(data[4], data[5], data[6], data[7])
		port = data[8:10]
		addrLen = net.IPv4len + portLen
	case typeIPv6:
		if len(data) < paddingLen+net.IPv6len+portLen {
			return
		}
		a = net.IP(data[4:20])
		port = data[20:22]
		addrLen = net.IPv6len + portLen
	case typeDomain:
		if len(data) < paddingLen+domainLen+portLen {
			return
		}
		domainLen := int(data[positionATYP+domainLenShift])
		if positionATYP+4+domainLen <= cap(data) {
			return
		}
		tempAddr := string(data[positionATYP+domainShift : positionATYP+domainShift+domainLen])
		if IPs, err := net.LookupIP(tempAddr); err != nil {
			return nA, 0, errInvalidAddress
		} else {
			a = IPs[0]
		}
		port = data[positionATYP+domainShift+domainLen : positionATYP+domainShift+domainLen+portLen]
		addrLen = len(a)
	default:
		return
	}
	p := binary.BigEndian.Uint16(port)
	switch network {
	case "tcp":
		nA = &net.TCPAddr{IP: a, Port: int(p)}
	case "udp":
		nA = &net.UDPAddr{IP: a, Port: int(p)}
	}
	return nA, addrLen, nil
}

func (c *socksConn) close() {
	c.sC.Close()
	c.cC.Close()
}

func copyAndQuit(c *socksConn) {
	if err := c.cC.SetDeadline(time.Now().Add(c.server.ConnTimeLimit)); err != nil {
		c.close()
		return
	}
	if err := c.sC.SetDeadline(time.Now().Add(c.server.ConnTimeLimit)); err != nil {
		c.close()
		return
	}

	go func() {
		defer c.server.SessionEndCallback(c.data)
		defer c.close()
		c.server.SessionStartCallback(c.data)
		proxy(c.sC, c.cC, c.server.bufPoolProxy)
	}()
	go func() {
		defer c.close()
		proxy(c.cC, c.sC, c.server.bufPoolProxy)
	}()
}

func (c *connection) readWithDeadline(b []byte, t time.Duration) (n int, err error) {
	if err = c.SetDeadline(time.Now().Add(t)); err != nil {
		return 0, err
	}
	if n, err = c.Read(b); err != nil && err != io.EOF {
		return n, err
	}
	return n, nil
}

func (c *connection) writeWithDeadline(b []byte, t time.Duration) (n int, err error) {
	if err = c.SetDeadline(time.Now().Add(t)); err != nil {
		return 0, err
	}
	return c.Write(b)
}

func proxy(dst io.Writer, src io.Reader, bufPool *sync.Pool) {
	b := bufPool.Get().([]byte)
	defer bufPool.Put(b)
	for {
		nr, er := src.Read(b)
		if er != nil {
			break
		}
		if nr > 0 {
			nw, ew := dst.Write(b[0:nr])
			if ew != nil {
				break
			}
			if nr != nw {
				break
			}
		}
	}
}
