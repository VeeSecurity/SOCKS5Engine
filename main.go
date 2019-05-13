package main

import (
	"flag"
	"fmt"
	"github.com/VeeSecurity/SOCKS5Engine/socks5"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"
)

var conf config

func listenForSIGUSR1(srv *socks5.Server) {
	sig := make(chan os.Signal)
	signal.Notify(sig, syscall.SIGUSR1)

	for {
		<-sig
		queue, authenticators, reqHandlers := srv.GetCurrentData()
		log.Println(
			fmt.Sprintf("\n"),
			fmt.Sprintf("Connection queue: %d\n", queue),
			fmt.Sprintf("Idle authenticators: %d\n", authenticators),
			fmt.Sprintf("Idle reqhandlers: %d\n", reqHandlers))
	}
}

func main() {

	const confMessage = "Full path to config. Refer to default VeeProxyEngine.conf for an example."

	v := flag.Bool("v", false, "version")
	h := flag.Bool("h", false, "help")
	pathToConfig := flag.String("conf", "/etc/VeeProxyEngine.conf", confMessage)
	flag.Parse()

	if *v {
		log.Panic(version)
	}

	if *h {
		log.Panic(help)
	}

	parseConfig(*pathToConfig)
	authProto, authNoneAllowed := generateAuthFuncPrototype()
	authFunc, startCallback, endCallback := setRedis(authProto)
	checkIP := generateCheckIP()
	localIP := net.ParseIP(conf.LocalIP)
	setRuntime()
	srv := &socks5.Server{
		Port:                   conf.Port,
		NumAuthWorkers:         conf.Authenticators,
		NumReqHandleWorkers:    conf.ReqHandlers,
		ConnQueueSize:          conf.ConnectionQueueSize,
		BufferSize:             conf.BufferSize,
		ConnTimeLimit:          time.Duration(conf.ConnLifetime) * time.Second,
		HandshakeStepTimeLimit: time.Duration(conf.HandshakeStepTimeout) * time.Second,
		CheckIP:                checkIP,
		AuthMethodNoneAllowed:  authNoneAllowed,
		Authenticate:           authFunc,
		SessionStartCallback:   startCallback,
		SessionEndCallback:     endCallback,
		LocalIP:                localIP,
	}
	if !conf.Logging {
		srv.SetLogger(log.New(ioutil.Discard, "", 0))
	}

	log.Println("running VPE")
	go listenForSIGUSR1(srv)

	srv.ListenAndServe()
}
