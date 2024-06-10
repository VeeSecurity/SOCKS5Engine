package main

import (
	"context"
	"errors"
	"layeh.com/radius"
	"log"
	"net"
	"time"
)

const (
	typeNASPortType         = 61
	valueNASPortTypeVirtual = 5
	typeNASIPAddress        = 4
	typeNASIdentifier       = 32
	typeServiceType         = 6
	valueServiceTypeFramed  = 2
	typeUserName            = 1
	typeUserPassword        = 2
)

func newAuthRadiusPacket() (packet *radius.Packet) {
	packet = radius.New(radius.CodeAccessRequest, []byte(conf.RadiusKey))

	nasPortType := radius.NewInteger(valueNASPortTypeVirtual)
	ipAddr, err := radius.NewIPAddr(net.ParseIP(conf.LocalIP))
	if err != nil {
		log.Panic(errors.New("can't use LocalIPv4IP for RADIUS"))
	}
	radID, err := radius.NewString("SOCKS5Engine")
	if err != nil {
		log.Panic(err)
	}
	serviceType := radius.NewInteger(valueServiceTypeFramed)
	packet.Attributes.Add(typeNASPortType, nasPortType)
	packet.Attributes.Add(typeNASIPAddress, ipAddr)
	packet.Attributes.Add(typeNASIdentifier, radID)
	packet.Attributes.Add(typeServiceType, serviceType)

	return
}

func authRadius(packet *radius.Packet, username, password string) (ok bool) {
	var u, p radius.Attribute
	var err error

	if u, err = radius.NewString(username); err != nil {
		return
	}
	if p, err = radius.NewUserPassword([]byte(password), []byte(conf.RadiusKey), packet.Authenticator[:]); err != nil {
		return
	}
	packet.Attributes.Set(typeUserName, u)
	packet.Attributes.Set(typeUserPassword, p)

	ctx, f := context.WithDeadline(context.Background(), time.Now().Add(time.Duration(conf.HandshakeStepTimeout)*time.Second))
	defer f()

	if response, err := radius.Exchange(ctx, packet, net.JoinHostPort(conf.RadiusIP, "1812")); err != nil {
		return false
	} else {
		return response.Code == radius.CodeAccessAccept
	}
}
