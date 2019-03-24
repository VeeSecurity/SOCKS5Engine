package socks5

// A spawner spawns workers.
type spawner interface {
	spawn()
}

type authenticatorSpawner struct {
	n               int
	authQueue       chan *authenticator
	reqHandlerQueue chan *reqHandler
}

type reqHandlerSpawner struct {
	n               int
	reqHandlerQueue chan *reqHandler
}

type authenticator struct {
	work            chan *socksConn
	authQueue       chan<- *authenticator
	reqHandlerQueue <-chan *reqHandler
}

type reqHandler struct {
	work            chan *socksConn
	reqHandlerQueue chan<- *reqHandler
}

// Runs the spawners and passes incoming requests to idle workers.
func dispatcher(connQueue chan *socksConn, authQueue chan *authenticator, spawners ...spawner) {
	for _, s := range spawners {
		s.spawn()
	}

	for {
		w := <-connQueue
		worker := <-authQueue
		worker.work <- w
	}
}

func (a authenticatorSpawner) spawn() {
	for i := 0; i < a.n; i++ {
		work := make(chan *socksConn)
		go (&authenticator{
			authQueue:       a.authQueue,
			work:            work,
			reqHandlerQueue: a.reqHandlerQueue,
		}).run()
	}
}

func (r reqHandlerSpawner) spawn() {
	for i := 0; i < r.n; i++ {
		work := make(chan *socksConn)
		go (&reqHandler{
			reqHandlerQueue: r.reqHandlerQueue,
			work:            work,
		}).run()
	}
}

func (a *authenticator) run() {
	for {
		a.authQueue <- a
		work := <-a.work
		if err := work.handshake(); err != nil {
			work.cC.Close()
		} else {
			worker := <-a.reqHandlerQueue
			worker.work <- work
		}
	}
}

func (rH *reqHandler) run() {
	for {
		rH.reqHandlerQueue <- rH
		work := <-rH.work
		if err := work.processRequest(); err != nil {
			work.cC.Close()
			if work.sC != nil {
				work.sC.Close()
			}
		}
	}
}
