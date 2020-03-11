package transport

import (
	"crypto/cipher"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"runtime"
	"runtime/debug"
	"strings"
	"time"

	"github.com/p9c/fec"
	log "github.com/p9c/logi"
	"github.com/p9c/gcm"
)

const (
	UDPMulticastAddress     = "224.0.0.1"
	success             int = iota // this is implicit zero of an int but starts the iota
	closed
	other
	DefaultPort = 11049
)

type (
	MsgBuffer struct {
		Buffers [][]byte
		First   time.Time
		Decoded bool
		Source  net.Addr
	}
	// HandlerFunc is a function that is used to process a received message
	HandlerFunc func(ctx interface{}, src net.Addr, dst string, b []byte) (err error)
	Handlers    map[string]HandlerFunc
	Channel     struct {
		buffers         map[string]*MsgBuffer
		Ready           chan struct{}
		context         interface{}
		Creator         string
		firstSender     *string
		lastSent        *time.Time
		MaxDatagramSize int
		receiveCiph     cipher.AEAD
		Receiver        *net.UDPConn
		sendCiph        cipher.AEAD
		Sender          *net.UDPConn
	}
)

// SetDestination changes the address the outbound connection of a channel directs to
func (c *Channel) SetDestination(dst string) (err error) {
	log.L.Debug("sending to", dst)
	if c.Sender, err = NewSender(dst, c.MaxDatagramSize); log.L.Check(err) {
	}
	return
}

// Send fires off some data through the configured channel's outbound.
func (c *Channel) Send(magic []byte, nonce []byte, data []byte) (n int, err error) {
	if len(data) == 0 {
		err = errors.New("not sending empty packet")
		log.L.Error(err)
		return
	}
	var msg []byte
	if msg, err = EncryptMessage(c.Creator, c.sendCiph, magic, nonce, data); log.L.Check(err) {
	}
	n, err = c.Sender.Write(msg)
	// log.L.DEBUG(msg)
	return
}

// SendMany sends a BufIter of shards as produced by GetShards
func (c *Channel) SendMany(magic []byte, b [][]byte) (err error) {
	if nonce, err := GetNonce(c.sendCiph); log.L.Check(err) {
	} else {
		for i := 0; i < len(b); i++ {
			// log.L.DEBUG(i)
			if _, err = c.Send(magic, nonce, b[i]); log.L.Check(err) {
				// debug.PrintStack()
			}
		}
		log.L.Trace(c.Creator, "sent packets", string(magic),
			hex.EncodeToString(nonce), c.Sender.LocalAddr(),
			c.Sender.RemoteAddr())
	}
	return
}

// Close the channel
func (c *Channel) Close() (err error) {
	// if err = c.Sender.Close(); log.L.Check(err) {
	// }
	// if err = c.Receiver.Close(); log.L.Check(err) {
	// }
	return
}

// GetShards returns a buffer iterator to feed to Channel.SendMany containing
// fec encoded shards built from the provided buffer
func GetShards(data []byte) (shards [][]byte) {
	var err error
	if shards, err = fec.Encode(data); log.L.Check(err) {
	}
	return
}

// NewUnicastChannel sets up a listener and sender for a specified destination
func NewUnicastChannel(creator string, ctx interface{}, key, sender, receiver string, maxDatagramSize int,
	handlers Handlers, quit chan struct{}) (channel *Channel, err error) {
	channel = &Channel{
		Creator:         creator,
		MaxDatagramSize: maxDatagramSize,
		buffers:         make(map[string]*MsgBuffer),
		context:         ctx,
	}
	var magics []string

	for i := range handlers {
		magics = append(magics, i)
	}
	// log.L.DEBUG("magics", magics, PrevCallers())
	if key != "" {
		if channel.sendCiph, err = gcm.GetCipher(key); log.L.Check(err) {
		}
		if channel.receiveCiph, err = gcm.GetCipher(key); log.L.Check(err) {
		}
	}
	channel.Receiver, err = Listen(receiver, channel, maxDatagramSize, handlers, quit)
	channel.Sender, err = NewSender(sender, maxDatagramSize)
	if err != nil {
		log.L.Error(err)
	}
	log.L.Warn("starting unicast channel:", channel.Creator, sender, receiver, magics)
	return
}

// NewSender creates a new UDP connection to a specified address
func NewSender(address string, maxDatagramSize int) (conn *net.UDPConn, err error) {
	var addr *net.UDPAddr
	if addr, err = net.ResolveUDPAddr("udp4", address); log.L.Check(err) {
		return
	} else if conn, err = net.DialUDP("udp4", nil, addr); log.L.Check(err) {
		debug.PrintStack()
		return
	}
	log.L.Debug("started new sender on", conn.LocalAddr(), "->", conn.RemoteAddr())
	if err = conn.SetWriteBuffer(maxDatagramSize); log.L.Check(err) {
	}
	return
}

// Listen binds to the UDP Address and port given and writes packets received
// from that Address to a buffer which is passed to a handler
func Listen(address string, channel *Channel, maxDatagramSize int, handlers Handlers,
	quit chan struct{}) (conn *net.UDPConn, err error) {
	var addr *net.UDPAddr
	if addr, err = net.ResolveUDPAddr("udp4", address); log.L.Check(err) {
		return
	} else if conn, err = net.ListenUDP("udp4", addr); log.L.Check(err) {
		return
	} else if conn == nil {
		return nil, errors.New("unable to start connection ")
	}
	log.L.Debug("starting listener on", conn.LocalAddr(), "->", conn.RemoteAddr())
	if err = conn.SetReadBuffer(maxDatagramSize); log.L.Check(err) {
		// not a critical error but should not happen
	}
	go Handle(address, channel, handlers, maxDatagramSize, quit)
	return
}

// NewBroadcastChannel returns a broadcaster and listener with a given handler on a multicast
// address and specified port. The handlers define the messages that will be processed and
// any other messages are ignored
func NewBroadcastChannel(creator string, ctx interface{}, key string, port int, maxDatagramSize int, handlers Handlers,
	quit chan struct{}) (channel *Channel, err error) {
	channel = &Channel{Creator: creator, MaxDatagramSize: maxDatagramSize,
		buffers: make(map[string]*MsgBuffer), context: ctx, Ready: make(chan struct{})}
	if key != "" {
		if channel.sendCiph, err = gcm.GetCipher(key); log.L.Check(err) {
		}
		if channel.receiveCiph, err = gcm.GetCipher(key); log.L.Check(err) {
		}
	}
	if channel.Receiver, err = ListenBroadcast(port, channel, maxDatagramSize, handlers, quit); log.L.Check(err) {
	}
	if channel.Sender, err = NewBroadcaster(port, maxDatagramSize); log.L.Check(err) {
	}
	close(channel.Ready)
	return
}

// NewBroadcaster creates a new UDP multicast connection on which to broadcast
func NewBroadcaster(port int, maxDatagramSize int) (conn *net.UDPConn, err error) {
	address := net.JoinHostPort(UDPMulticastAddress, fmt.Sprint(port))
	if conn, err = NewSender(address, maxDatagramSize); log.L.Check(err) {
	}
	return
}

// ListenBroadcast binds to the UDP Address and port given and writes packets received
// from that Address to a buffer which is passed to a handler
func ListenBroadcast(port int, channel *Channel, maxDatagramSize int, handlers Handlers,
	quit chan struct{}) (conn *net.UDPConn, err error) {
	address := net.JoinHostPort(UDPMulticastAddress, fmt.Sprint(port))
	var addr *net.UDPAddr
	// Parse the string Address
	if addr, err = net.ResolveUDPAddr("udp4", address); log.L.Check(err) {
		return
		// Open up a connection
	} else if conn, err = net.ListenMulticastUDP("udp4", nil, addr); log.L.Check(err) {
		return
	} else if conn == nil {
		return nil, errors.New("unable to start connection ")
	}
	var magics []string
	for i := range handlers {
		magics = append(magics, i)
	}
	// log.L.DEBUG("magics", magics, PrevCallers())
	log.L.Info("starting broadcast listener", channel.Creator, address, magics)
	if err = conn.SetReadBuffer(maxDatagramSize); log.L.Check(err) {
	}
	channel.Receiver = conn
	go Handle(address, channel, handlers, maxDatagramSize, quit)
	return
}

func handleNetworkError(address string, err error) (result int) {
	if len(strings.Split(err.Error(), "use of closed network connection")) >= 2 {
		log.L.Debug("connection closed", address)
		result = closed
	} else {
		log.L.Errorf("ReadFromUDP failed: '%s'", err)
		result = other
	}
	return
}

// Handle listens for messages, decodes them, aggregates them, recovers the data from the
// reed solomon fec shards received and invokes the handler provided matching the magic
// on the complete received messages
func Handle(address string, channel *Channel,
	handlers Handlers, maxDatagramSize int, quit chan struct{}) {
	buffer := make([]byte, maxDatagramSize)
	log.L.Warn("starting handler for", channel.Creator, "listener")
	// Loop forever reading from the socket until it is closed
	// seenNonce := ""
	var err error
	var numBytes int
	var src net.Addr
	// var seenNonce string
	<-channel.Ready
out:
	for {
		select {
		case <-quit:
			break out
		default:
		}
		if numBytes, src, err = channel.Receiver.ReadFromUDP(buffer); log.L.Check(err) {
			switch handleNetworkError(address, err) {
			case closed:
				break out
			case other:
				continue
			case success:
			}
		}
		// Filter messages by magic, if there is no match in the map the packet is ignored
		magic := string(buffer[:4])
		if handler, ok := handlers[magic]; ok {
			// if caller needs to know the liveness status of the
			// controller it is working on, the code below
			if channel.lastSent != nil && channel.firstSender != nil {
				*channel.lastSent = time.Now()
			}
			msg := buffer[:numBytes]
			nL := channel.receiveCiph.NonceSize()
			nonceBytes := msg[4 : 4+nL]
			nonce := string(nonceBytes)
			// if nonce == seenNonce {
			// 	log.L.DEBUG("seen this one")
			// 	continue
			// }
			// seenNonce = nonce
			// decipher
			var shard []byte
			if shard, err = channel.receiveCiph.Open(nil, nonceBytes, msg[4+len(nonceBytes):], nil); err != nil {
				continue
			}
			// log.L.DEBUG("read", numBytes, "from", src, err, hex.EncodeToString(msg))
			if bn, ok := channel.buffers[nonce]; ok {
				if !bn.Decoded {
					bn.Buffers = append(bn.Buffers, shard)
					if len(bn.Buffers) >= 3 {
						// log.L.DEBUG(len(bn.Buffers))
						// try to decode it
						var cipherText []byte
						cipherText, err = fec.Decode(bn.Buffers)
						if err != nil {
							log.L.Error(err)
							continue
						}
						bn.Decoded = true
						// log.L.DEBUG(numBytes, src, err)
						if err = handler(channel.context, src, address, cipherText); log.L.Check(err) {
							continue
						}
						// src = nil
						// buffer = buffer[:0]
					}
				} else {
					// if nonce == seenNonce {
					// 	continue
					// }
					// seenNonce = nonce
					for i := range channel.buffers {
						if i != nonce || (channel.buffers[i].Decoded &&
							len(channel.buffers[i].Buffers) > 8) {
							// superseded messages can be deleted from the
							// buffers, we don't add more data for the already
							// decoded.
							delete(channel.buffers, i)
						}
					}
				}
			} else {
				channel.buffers[nonce] = &MsgBuffer{[][]byte{},
					time.Now(), false, src}
				channel.buffers[nonce].Buffers = append(channel.buffers[nonce].
					Buffers, shard)
			}
		}
		// for i := range buffer {
		// 	buffer[i] = 0
		// }
	}
}

func PrevCallers() (out string) {
	for i := 0; i < 10; i++ {
		_, loc, iline, _ := runtime.Caller(i)
		out += fmt.Sprintf("%s:%d \n", loc, iline)
	}
	return
}
