package socks5

import (
	"errors"
	"log"
	"net"
	"os"
	"sync"
	"time"
)

// socks5 as a package works right out of the box with the constants below
const (
	port                = 1080
	numAuthWorkers      = 500
	numReqHandleWorkers = 500
	connQueueSize       = 500

	bufferSize             = 5
	connTimeLimit          = 15 * time.Minute
	handshakeStepTimeLimit = 1 * time.Second
)

type AuthFunc func(username, password string) (bool, interface{})
type CheckIPFunc func(ip net.IP) bool
type GenericCallbackFunc func(i interface{})

type Server struct {
	Port int

	// Workers are used to balance requests. There are two groups of subsequent workers: Authenticators and ReqHandlers.
	NumAuthWorkers      int
	NumReqHandleWorkers int

	// Size of the queue for the requests to be queue when all workers are idle. If the queue becomes full,
	// TCP listener blocks.
	ConnQueueSize int

	lg                     *log.Logger
	BufferSize             int
	ConnTimeLimit          time.Duration
	HandshakeStepTimeLimit time.Duration

	CheckIP CheckIPFunc

	// The 2 basic authentication methods in socks5 are the username/password subnegotiation and no authentication.
	// AuthMethodNoneAllowed will authenticate any requests that declare this method as valid.
	AuthMethodNoneAllowed bool

	// Returns a bool result of whether a request is authenticated.
	// It can also return a interface{} value that will be attached to a session and passed to
	// the callbacks when proxying starts and ends. This makes proxy sessions identifiable.
	Authenticate AuthFunc

	// The callback is called when the server starts proxying a session.
	// The value returned from AuthFunc is used as an argument for GenericCallbackFunc,
	// thus making it possible to store and handle data associated with a session.
	SessionStartCallback GenericCallbackFunc

	// Respectively to SessionStartCallback, SessionEndCallback is called once a session is canceled.
	SessionEndCallback GenericCallbackFunc

	LocalIP    net.IP
	getLocalIP func() ([]byte, error)

	connQueue          chan *socksConn
	authenticatorQueue chan *authenticator
	reqHandlerQueue    chan *reqHandler

	bufPoolLarge *sync.Pool
	bufPoolSmall *sync.Pool
	bufPoolProxy *sync.Pool

	isSetLg bool

	mu sync.Mutex
}

func (srv *Server) setFields() {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	if srv.Port <= 0 {
		srv.Port = port
	}
	if srv.NumAuthWorkers <= 0 {
		srv.NumAuthWorkers = numAuthWorkers
	}
	if srv.NumReqHandleWorkers <= 0 {
		srv.NumReqHandleWorkers = numReqHandleWorkers
	}
	if srv.ConnQueueSize <= 0 {
		srv.ConnQueueSize = connQueueSize
	}
	if srv.BufferSize <= 0 {
		srv.BufferSize = bufferSize
	}
	if srv.ConnTimeLimit <= 0 {
		srv.ConnTimeLimit = connTimeLimit
	}
	if srv.HandshakeStepTimeLimit <= 0 {
		srv.HandshakeStepTimeLimit = handshakeStepTimeLimit
	}
	if srv.CheckIP == nil {
		srv.CheckIP = func(ip net.IP) bool {
			return true
		}
	}
	if srv.Authenticate == nil {
		srv.Authenticate = func(u, p string) (bool, interface{}) {
			return true, nil
		}
	}
	if srv.SessionStartCallback == nil {
		srv.SessionStartCallback = func(i interface{}) {
			return
		}
	}
	if srv.SessionEndCallback == nil {
		srv.SessionEndCallback = func(i interface{}) {
			return
		}
	}
	if srv.LocalIP == nil {
		srv.getLocalIP = func() ([]byte, error) {
			addrs, err := net.InterfaceAddrs()
			if err != nil {
				return nil, err
			}
			for _, a := range addrs {
				if ipNet, ok := a.(*net.IPNet); ok && !ipNet.IP.IsLoopback() {
					if ipCandidate := ipNet.IP.To4(); ipCandidate != nil {
						return ipCandidate, nil
					}
				}
			}
			return nil, errors.New("couldn't find an IP-address")
		}
	} else {
		srv.getLocalIP = func() ([]byte, error) {
			return srv.LocalIP, nil
		}
	}
	if !srv.isSetLg {
		srv.mu.Unlock()
		srv.SetLogger(log.New(os.Stdout, "", log.Llongfile))
		srv.mu.Lock()
	}
	srv.bufPoolSmall = &sync.Pool{
		New: func() interface{} {
			return make([]byte, 262)
		},
	}
	srv.bufPoolLarge = &sync.Pool{
		New: func() interface{} {
			return make([]byte, 513)
		},
	}
	srv.bufPoolProxy = &sync.Pool{
		New: func() interface{} {
			return make([]byte, 1024*srv.BufferSize)
		},
	}

	srv.authenticatorQueue = make(chan *authenticator, srv.NumAuthWorkers)
	srv.reqHandlerQueue = make(chan *reqHandler, srv.NumReqHandleWorkers)
	srv.connQueue = make(chan *socksConn, srv.ConnQueueSize)
}

func (srv *Server) SetLogger(logger *log.Logger) {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	srv.isSetLg = true
	srv.lg = logger
}

func (srv *Server) runDispatcher() {
	go dispatcher(srv.connQueue, srv.authenticatorQueue,
		authenticatorSpawner{
			n:               srv.NumAuthWorkers,
			authQueue:       srv.authenticatorQueue,
			reqHandlerQueue: srv.reqHandlerQueue,
		},
		reqHandlerSpawner{
			n:               srv.NumReqHandleWorkers,
			reqHandlerQueue: srv.reqHandlerQueue,
		},
	)
}

func (srv *Server) ListenAndServe() {
	srv.setFields()
	srv.runDispatcher()
	ln, err := net.ListenTCP("tcp", &net.TCPAddr{Port: srv.Port})
	if err != nil {
		log.Panic(err)
	}
	for {
		c, err := ln.AcceptTCP()
		if err != nil {
			continue
		}
		srv.connQueue <- &socksConn{
			cC:     &connection{c},
			server: srv,
		}
	}
}

func (srv *Server) GetCurrentData() (queue, authenticators, reqHandlers int) {
	return len(srv.connQueue), len(srv.authenticatorQueue), len(srv.reqHandlerQueue)
}
