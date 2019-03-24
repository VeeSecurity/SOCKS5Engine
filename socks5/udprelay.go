package socks5

import (
	"bytes"
	"encoding/binary"
	"net"
	"sync"
	"time"
)

type relay struct {
	m        *sync.Mutex
	initConn *connection
	client   struct {
		conn    *net.UDPConn
		address *net.UDPAddr
		IP      net.IP
	}
	peer struct {
		conn    *net.UDPConn
		address *net.UDPAddr
	}
	header []byte
	server *Server
}

func relayTakeOver(c *connection, srv *Server) {
	var (
		err error
		r   = &relay{initConn: c, m: &sync.Mutex{}, server: srv}
	)

	if r.client.conn, err = net.ListenUDP("udp", nil); err != nil {
		return
	}
	r.client.IP = r.initConn.RemoteAddr().(*net.TCPAddr).IP
	if r.peer.conn, err = net.ListenUDP("udp", nil); err != nil {
		r.client.conn.Close()
		return
	}
	if err := r.process(); err != nil {
		r.client.conn.Close()
		r.peer.conn.Close()
		return
	}
}

func (r *relay) process() (err error) {
	var (
		n           int
		ip, port, b []byte
		addressType byte
	)

	defer func() {
		if err != nil {
			r.server.lg.Println(err.Error())
		}
	}()

	if addressType, ip, port, err = getLocalUDPAddress(r.server, r.client.conn); err != nil {
		return err
	}

	b = []byte{socks5Version, responseSuccess, valueReserved, addressType}
	b = append(b, ip...)
	b = append(b, port...)
	if _, err = r.initConn.writeWithDeadline(b, r.server.HandshakeStepTimeLimit); err != nil {
		return err
	}

	if err = r.client.conn.SetReadDeadline(time.Now().Add(r.server.HandshakeStepTimeLimit)); err != nil {
		return err
	}

	b = r.server.bufPoolProxy.Get().([]byte)
	defer r.server.bufPoolProxy.Put(b)

	n, r.client.address, err = r.client.conn.ReadFromUDP(b)
	if err != nil {
		return err
	} else if b[positionFRAG] != 0 || n-2 <= positionAddress {
		return errCorruptedPacket
	} else if !r.client.IP.Equal(r.client.address.IP) {
		return errInvalidAddress
	}

	peerAddr, addrLen, err := evalDestination("udp", b)
	if err != nil {
		return err
	}
	r.peer.address = peerAddr.(*net.UDPAddr)
	r.header = make([]byte, 4+addrLen)
	copy(r.header, b[:4+addrLen])
	if err = r.peer.conn.SetWriteDeadline(time.Now().Add(r.server.HandshakeStepTimeLimit)); err != nil {
		return err
	}
	if _, err = r.peer.conn.WriteToUDP(b[4+addrLen:], r.peer.address); err != nil {
		return err
	}
	go r.proxyUDP()
	return nil
}

func (r *relay) close() {
	r.initConn.Close()
	r.peer.conn.Close()
	r.client.conn.Close()
}

func (r *relay) proxyUDP() {
	if err := r.initConn.SetDeadline(time.Now().Add(r.server.ConnTimeLimit)); err != nil {
		r.close()
		return
	}
	if err := r.peer.conn.SetDeadline(time.Now().Add(r.server.ConnTimeLimit)); err != nil {
		r.close()
		return
	}
	if err := r.client.conn.SetDeadline(time.Now().Add(r.server.ConnTimeLimit)); err != nil {
		r.close()
		return
	}

	go func() {
		defer r.close()
		b := r.server.bufPoolProxy.Get().([]byte)
		defer r.server.bufPoolProxy.Put(b)

		for {
			n, _, err := r.peer.conn.ReadFromUDP(b)
			if err != nil {
				break
			}
			r.m.Lock()
			copy(b[len(r.header):], b[:n])
			copy(b[:len(r.header)], r.header)
			_, err = r.client.conn.WriteToUDP(b[:n+len(r.header)], r.client.address)
			r.m.Unlock()
			if err != nil {
				break
			}
		}
	}()

	go func() {
		defer r.close()
		b := r.server.bufPoolProxy.Get().([]byte)
		defer r.server.bufPoolProxy.Put(b)

		for {
			n, a, err := r.client.conn.ReadFromUDP(b)
			if err != nil {
				return
			} else if !a.IP.Equal(r.client.address.IP) {
				continue
			}
			address, addrLen, err := evalDestination("udp", b)
			if err != nil {
				return
			}
			r.m.Lock()
			r.peer.address = address.(*net.UDPAddr)
			copy(r.header, b[:4+addrLen])
			r.m.Unlock()
			if _, err := r.peer.conn.WriteToUDP(b[4+addrLen:n], r.peer.address); err != nil {
				return
			}
		}
	}()
}

func getLocalUDPAddress(srv *Server, conn *net.UDPConn) (addressType byte, ip, port []byte, err error) {
	ip, err = srv.getLocalIP()
	if err != nil {
		return
	}
	la, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return 0x00, nil, nil, errUnknown
	}
	portBuff := new(bytes.Buffer)
	if err = binary.Write(portBuff, binary.BigEndian, uint16(la.Port)); err != nil {
		return 0, nil, nil, err
	}
	addressType = typeIPv4
	return addressType, ip, portBuff.Bytes(), nil
}
