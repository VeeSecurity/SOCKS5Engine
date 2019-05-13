package main

import (
	"bufio"
	"fmt"
	"github.com/BurntSushi/toml"
	"github.com/VeeSecurity/SOCKS5Engine/socks5"
	"github.com/go-redis/redis"
	"io/ioutil"
	"layeh.com/radius"
	"log"
	"net"
	"os"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"
)

type credentials map[string]string

type config struct {
	Port                int    `toml:"port"`
	Authenticators      int    `toml:"authenticators"`
	ReqHandlers         int    `toml:"reqHandlers"`
	ConnectionQueueSize int    `toml:"connectionQueue"`
	LocalIP             string `toml:"localIP"`

	Dev     bool `toml:"dev"`
	Logging bool `toml:"logging"`

	GCC        int `toml:"GC"`
	Processes  int `toml:"processes"`
	BufferSize int `toml:"buffer"`

	ConnLifetime         int `toml:"connLifetime"`
	HandshakeStepTimeout int `toml:"handshakeStepTimeout"`

	SubnetWhitelist []string `toml:"subnetWhitelist"`
	SubnetBlacklist []string `toml:"subnetBlacklist"`

	Auth     string `toml:"auth"`
	NoAuth   bool   `toml:"noauth"`
	AuthFile string `toml:"authFile"`

	RadiusIP  string `toml:"radiusIP"`
	RadiusKey string `toml:"radiusKey"`

	Redis           bool   `toml:"redis"`
	CacheTimeout    int    `toml:"cacheTimeout"`
	SessionTracking bool   `toml:"sessionTracking"`
	SessionLimit    int    `toml:"sessionLimit"`
	RedisIP         string `toml:"redisIP"`
	RedisPort       int    `toml:"redisPort"`
	RedisDB         int    `toml:"redisDB"`
	RedisPassword   string `toml:"redisPassword"`
}

func parseConfig(pathToConfig string) {
	dat, err := ioutil.ReadFile(pathToConfig)
	if err != nil {
		log.Panic("couldn't read the configuration file")
	}

	if _, err := toml.Decode(string(dat), &conf); err != nil {
		log.Panic("invalid configuration file")
	}

	return
}

func generateAuthFuncPrototype() (auth socks5.AuthFunc, authNoneAllowed bool) {
	if conf.NoAuth {
		authNoneAllowed = true
	}

	if conf.Dev {
		auth = func(username, password string) (bool, interface{}) {
			return true, username
		}
		return
	}

	switch strings.ToLower(conf.Auth) {
	case "radius":
		radiusPool := &sync.Pool{
			New: func() interface{} {
				return newAuthRadiusPacket()
			},
		}
		auth = func(username, password string) (bool, interface{}) {
			packet := radiusPool.Get().(*radius.Packet)
			defer radiusPool.Put(packet)
			return authRadius(packet, username, password), username
		}
	case "explicit":
		file, err := os.Open(conf.AuthFile)
		if err != nil {
			log.Panic("couldn't open file with auth data: ", conf.AuthFile)
		}
		defer file.Close()

		var authList = make(credentials)
		var scanner = bufio.NewScanner(file)

		for scanner.Scan() {
			s := scanner.Text()
			if n := strings.Count(s, ":"); n != 1 && s != "" {
				log.Panic("each entry in a file with auth data must contain exactly one colon")
			} else if s != "" {
				chunks := strings.Split(s, ":")
				authList[chunks[0]] = chunks[1]
			}
		}
		auth = func(username, password string) (bool, interface{}) {
			return authList[username] == password, username
		}
	default:
		log.Panic("invalid Auth option")
	}

	return
}

func setRedis(currentAuthFunc socks5.AuthFunc) (auth socks5.AuthFunc, start, end socks5.GenericCallbackFunc) {
	var trackSessions func(username string) bool

	if !conf.Redis {
		auth = currentAuthFunc
		return
	}

	if conf.RedisPort <= 0 {
		log.Panic("invalid redisPort")
	}
	port := strconv.FormatInt(int64(conf.RedisPort), 10)
	redisCl := createRedisClient(conf.RedisIP, port, conf.RedisPassword, conf.RedisDB, conf.CacheTimeout)
	redisCl.FlushDB()

	if !conf.SessionTracking {
		trackSessions = func(username string) bool {
			return true
		}
	} else {
		trackSessions = func(username string) bool {
			sessionKey := fmt.Sprintf("%s:sessions", username)
			s, err := redisCl.Get(sessionKey).Int64()
			if err != nil && err != redis.Nil {
				return false
			}

			return s < int64(conf.SessionLimit)
		}
	}

	auth = func(username, password string) (b bool, i interface{}) {
		passKey := fmt.Sprintf("%s:pass", username)

		defer func() {
			if b {
				redisCl.Set(passKey, password, time.Duration(conf.CacheTimeout)*time.Second)
			}
		}()

		if password == redisCl.Get(passKey).String() {
			return trackSessions(username), username
		}

		b, _ = currentAuthFunc(username, password)
		return b && trackSessions(username), username
	}

	if !conf.SessionTracking {
		return
	}

	start = func(i interface{}) {
		u, ok := i.(string)
		if !ok {
			return
		}
		key := fmt.Sprintf("%s:sessions", u)
		redisCl.Incr(key)
		redisCl.Expire(key, time.Duration(conf.ConnLifetime)*time.Second)
	}
	end = func(i interface{}) {
		u, ok := i.(string)
		if !ok {
			return
		}
		key := fmt.Sprintf("%s:sessions", u)
		redisCl.Decr(key)
		redisCl.Expire(key, time.Duration(conf.ConnLifetime)*time.Second)
	}
	return
}

func generateCheckIP() (checkIP socks5.CheckIPFunc) {
	generator := func(nets []net.IPNet, opt1, opt2 bool) socks5.CheckIPFunc {
		return func(ip net.IP) bool {
			for _, n := range nets {
				if n.Contains(ip) {
					return opt1
				}
			}
			return opt2
		}
	}
	if len(conf.SubnetWhitelist) != 0 {
		nets := populateNets(conf.SubnetWhitelist)
		checkIP = generator(nets, true, false)
	} else if len(conf.SubnetBlacklist) != 0 {
		nets := populateNets(conf.SubnetBlacklist)
		checkIP = generator(nets, false, true)
	}
	return
}

func setRuntime() {
	if conf.Processes <= 0 {
		log.Panic("invalid processes value")
	} else {
		runtime.GOMAXPROCS(conf.Processes)
	}
	debug.SetGCPercent(conf.GCC)
}

func createRedisClient(ip, port, password string, db int, cacheTimeLimit int) *redis.Client {
	if cacheTimeLimit <= 0 {
		log.Panic("invalid cacheTimeout")
	}

	if db < 0 {
		log.Panic("invalid redisDB")
	}
	return redis.NewClient(&redis.Options{
		Addr:     net.JoinHostPort(ip, port),
		Password: password,
		DB:       db,
	})
}

func populateNets(CIDRs []string) (nets []net.IPNet) {
	nets = make([]net.IPNet, len(CIDRs))
	for _, n := range CIDRs {
		_, N, err := net.ParseCIDR(n)
		if err != nil {
			log.Panic(err)
		}
		nets = append(nets, *N)
	}
	return nets
}
