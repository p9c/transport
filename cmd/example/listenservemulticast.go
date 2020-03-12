package main

import (
	"fmt"
	"net"
	"time"

	log "github.com/p9c/logi"

	"github.com/p9c/transport"
)

const (
	TestMagic = "TEST"
)

var (
	TestMagicB = []byte(TestMagic)
)

func main() {
	log.L.SetLevel("trace", true, "transport")
	quit := make(chan struct{})
	if c, err := transport.NewBroadcastChannel("test", nil, "cipher",
		1234, 8192, transport.Handlers{
			TestMagic: func(ctx interface{}, src net.Addr, dst string,
				b []byte) (err error) {
				log.L.Infof("%s <- %s [%d] '%s'", src.String(), dst, len(b), string(b))
				return
			},
		},
		quit,
	); log.L.Check(err) {
		panic(err)
	} else {
		var n int
		for i := 0; i < 10; i++ {
			text := []byte(fmt.Sprintf("this is a test %d", i))
			if err = c.SendMany(TestMagicB, transport.GetShards(text)); log.L.Check(err) {
			} else {
				log.L.Infof("%s -> %s [%d] '%s'",
					c.Sender.LocalAddr(), c.Sender.RemoteAddr(), n-4, text)
			}
		}
		close(quit)
		if err = c.Close(); !log.L.Check(err) {
			time.Sleep(time.Second * 1)
		}
	}
}
