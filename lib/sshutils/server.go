/*
Copyright 2015 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

This file contains the implementations of sshutils.Server class.
It is the underlying "base SSH server" for everything in Teleport.

*/

package sshutils

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/limiter"
	"github.com/gravitational/teleport/lib/utils"

	"github.com/gravitational/trace"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

// Server is a generic implementation of an SSH server. All Teleport
// services (auth, proxy, ssh) use this as a base to accept SSH connections.
type Server struct {
	*log.Entry
	sync.RWMutex

	// component is a name of the facility which uses this server,
	// used for logging/debugging. typically it's "proxy" or "auth api", etc
	component string

	// addr is the address this server binds to and listens on
	addr utils.NetAddr

	// listener is usually the listening TCP/IP socket
	listener net.Listener

	newChanHandler NewChanHandler
	reqHandler     RequestHandler

	cfg     ssh.ServerConfig
	limiter *limiter.Limiter

	listenerClosed bool

	closeContext context.Context
	closeFunc    context.CancelFunc
}

const (
	// SSHVersionPrefix is the prefix of "server version" string which begins
	// every SSH handshake. It MUST start with "SSH-2.0" according to
	// https://tools.ietf.org/html/rfc4253#page-4
	SSHVersionPrefix = "SSH-2.0-Teleport"

	// ProxyHelloSignature is a string which Teleport proxy will send
	// right after the initial SSH "handshake/version" message if it detects
	// talking to a Teleport server.
	ProxyHelloSignature = "Teleport-Proxy"

	// MaxVersionStringBytes is the maximum number of bytes allowed for a
	// SSH version string
	// https://tools.ietf.org/html/rfc4253
	MaxVersionStringBytes = 255

	// TrueClientAddrVar environment variable is used by the web UI to pass
	// the remote IP (user's IP) from the browser/HTTP session into an SSH session
	TrueClientAddrVar = "TELEPORT_CLIENT_ADDR"
)

// ServerOption is a functional argument for server
type ServerOption func(cfg *Server) error

func SetLimiter(limiter *limiter.Limiter) ServerOption {
	return func(s *Server) error {
		s.limiter = limiter
		return nil
	}
}

func NewServer(
	component string,
	a utils.NetAddr,
	h NewChanHandler,
	hostSigners []ssh.Signer,
	ah AuthMethods,
	opts ...ServerOption) (*Server, error) {

	err := checkArguments(a, h, hostSigners, ah)
	if err != nil {
		return nil, err
	}

	closeContext, cancel := context.WithCancel(context.TODO())
	s := &Server{
		Entry: log.WithFields(log.Fields{
			trace.Component: "ssh:" + component,
		}),
		addr:           a,
		newChanHandler: h,
		component:      component,
		closeContext:   closeContext,
		closeFunc:      cancel,
	}
	s.limiter, err = limiter.NewLimiter(limiter.LimiterConfig{})
	if err != nil {
		return nil, trace.Wrap(err)
	}

	for _, o := range opts {
		if err := o(s); err != nil {
			return nil, err
		}
	}
	for _, signer := range hostSigners {
		(&s.cfg).AddHostKey(signer)
	}
	s.cfg.PublicKeyCallback = ah.PublicKey
	s.cfg.PasswordCallback = ah.Password
	s.cfg.NoClientAuth = ah.NoClient

	// Teleport SSH server will be sending the following "version string" during
	// SSH handshake (example): "SSH-2.0-T eleport 1.5.1-beta" (space is important!)
	s.cfg.ServerVersion = fmt.Sprintf("%s %s", SSHVersionPrefix, teleport.Version)
	return s, nil
}

func SetSSHConfig(cfg ssh.ServerConfig) ServerOption {
	return func(s *Server) error {
		s.cfg = cfg
		return nil
	}
}

func SetRequestHandler(req RequestHandler) ServerOption {
	return func(s *Server) error {
		s.reqHandler = req
		return nil
	}
}

func SetCiphers(ciphers []string) ServerOption {
	return func(s *Server) error {
		s.Debugf("supported ciphers: %q", ciphers)
		if ciphers != nil {
			s.cfg.Ciphers = ciphers
		}
		return nil
	}
}

func SetKEXAlgorithms(kexAlgorithms []string) ServerOption {
	return func(s *Server) error {
		s.Debugf("supported KEX algorithms: %q", kexAlgorithms)
		if kexAlgorithms != nil {
			s.cfg.KeyExchanges = kexAlgorithms
		}
		return nil
	}
}

func SetMACAlgorithms(macAlgorithms []string) ServerOption {
	return func(s *Server) error {
		s.Debugf("supported MAC algorithms: %q", macAlgorithms)
		if macAlgorithms != nil {
			s.cfg.MACs = macAlgorithms
		}
		return nil
	}
}

func (s *Server) Addr() string {
	return s.listener.Addr().String()
}

func (s *Server) isClosed() bool {
	s.RLock()
	defer s.RUnlock()
	return s.listenerClosed
}

func (s *Server) Serve(listener net.Listener) error {
	if err := s.setListener(listener); err != nil {
		return trace.Wrap(err)
	}
	s.acceptConnections()
	return nil
}

func (s *Server) Start() error {
	listener, err := net.Listen(s.addr.AddrNetwork, s.addr.Addr)
	if err != nil {
		return trace.ConvertSystemError(err)
	}
	if err := s.setListener(listener); err != nil {
		return trace.Wrap(err)
	}
	go s.acceptConnections()
	return nil
}

func (s *Server) setListener(l net.Listener) error {
	s.Lock()
	defer s.Unlock()
	if s.listener != nil {
		return trace.BadParameter("listener is already set to %v", s.listener.Addr())
	}
	s.listenerClosed = false
	s.listener = l
	return nil
}

// Wait waits until server stops serving new connections
// on the listener socket
func (s *Server) Wait() {
	<-s.closeContext.Done()
}

// Close closes listening socket and stops accepting connections
func (s *Server) Close() error {
	s.Lock()
	defer s.Unlock()

	// listener already closed, nothing to do
	if s.listenerClosed {
		return nil
	}

	s.listenerClosed = true
	if s.listener != nil {
		err := s.listener.Close()
		return err
	}
	return nil
}

func (s *Server) acceptConnections() {
	defer s.closeFunc()
	backoffTimer := time.NewTicker(5 * time.Second)
	defer backoffTimer.Stop()
	addr := s.Addr()
	s.Debugf("listening on %v", addr)
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			if s.isClosed() {
				s.Debugf("server %v has closed", addr)
				return
			}
			select {
			case <-s.closeContext.Done():
				s.Debugf("server %v has closed", addr)
				return
			case <-backoffTimer.C:
				s.Debugf("backoff on network error: %v", err)
			}
		} else {
			go s.handleConnection(conn)
		}
	}
}

// handleConnection is called every time an SSH server accepts a new
// connection from a client.
//
// this is the foundation of all SSH connections in Teleport (between clients
// and proxies, proxies and servers, servers and auth, etc).
//
func (s *Server) handleConnection(conn net.Conn) {
	// initiate an SSH connection, note that we don't need to close the conn here
	// in case of error as ssh server takes care of this
	remoteAddr, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		log.Errorf(err.Error())
	}
	if err := s.limiter.AcquireConnection(remoteAddr); err != nil {
		log.Errorf(err.Error())
		conn.Close()
		return
	}
	defer s.limiter.ReleaseConnection(remoteAddr)

	// apply idle read/write timeout to this connection.
	conn = utils.ObeyIdleTimeout(conn,
		defaults.DefaultIdleConnectionDuration,
		s.component)

	// create a new SSH server which handles the handshake (and pass the custom
	// payload structure which will be populated only when/if this connection
	// comes from another Teleport proxy):
	sconn, chans, reqs, err := ssh.NewServerConn(wrapConnection(conn), &s.cfg)
	if err != nil {
		conn.SetDeadline(time.Time{})
		return
	}

	user := sconn.User()
	if err := s.limiter.RegisterRequest(user); err != nil {
		log.Errorf(err.Error())
		sconn.Close()
		conn.Close()
		return
	}
	// Connection successfully initiated
	s.Debugf("incoming connection %v -> %v vesion: %v",
		sconn.RemoteAddr(), sconn.LocalAddr(), string(sconn.ClientVersion()))

	// will be called when the connection is closed
	connClosed := func() {
		s.Debugf("closed connection %v", sconn.RemoteAddr())
	}

	// The keepalive ticket will ensure that SSH keepalive requests are being sent
	// to the client at an interval much shorter than idle connection kill switch
	keepAliveTick := time.NewTicker(defaults.DefaultIdleConnectionDuration / 3)
	defer keepAliveTick.Stop()
	keepAlivePayload := [8]byte{0}

	for {
		select {
		// handle out of band ssh requests
		case req := <-reqs:
			if req == nil {
				connClosed()
				return
			}
			s.Debugf("received out-of-band request: %+v", req)
			if s.reqHandler != nil {
				go s.reqHandler.HandleRequest(req)
			}
			// handle channels:
		case nch := <-chans:
			if nch == nil {
				connClosed()
				return
			}
			go s.newChanHandler.HandleNewChan(conn, sconn, nch)
			// send keepalive pings to the clients
		case <-keepAliveTick.C:
			const wantReply = true
			sconn.SendRequest(teleport.KeepAliveReqType, wantReply, keepAlivePayload[:])
		}
	}
}

type RequestHandler interface {
	HandleRequest(r *ssh.Request)
}

type RequestHandlerFunc func(*ssh.Request)

func (f RequestHandlerFunc) HandleRequest(r *ssh.Request) {
	f(r)
}

type NewChanHandler interface {
	HandleNewChan(net.Conn, *ssh.ServerConn, ssh.NewChannel)
}

type NewChanHandlerFunc func(net.Conn, *ssh.ServerConn, ssh.NewChannel)

func (f NewChanHandlerFunc) HandleNewChan(conn net.Conn, sshConn *ssh.ServerConn, ch ssh.NewChannel) {
	f(conn, sshConn, ch)
}

type AuthMethods struct {
	PublicKey PublicKeyFunc
	Password  PasswordFunc
	NoClient  bool
}

func checkArguments(a utils.NetAddr, h NewChanHandler, hostSigners []ssh.Signer, ah AuthMethods) error {
	if a.Addr == "" || a.AddrNetwork == "" {
		return trace.BadParameter("addr: specify network and the address for listening socket")
	}

	if h == nil {
		return trace.BadParameter("missing NewChanHandler")
	}
	if len(hostSigners) == 0 {
		return trace.BadParameter("need at least one signer")
	}
	for _, s := range hostSigners {
		if s == nil {
			return trace.BadParameter("host signer can not be nil")
		}
	}
	if ah.PublicKey == nil && ah.Password == nil && ah.NoClient == false {
		return trace.BadParameter("need at least one auth method")
	}
	return nil
}

type PublicKeyFunc func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error)
type PasswordFunc func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error)

// KeysEqual is constant time compare of the keys to avoid timing attacks
func KeysEqual(ak, bk ssh.PublicKey) bool {
	a := ssh.Marshal(ak)
	b := ssh.Marshal(bk)
	return (len(a) == len(b) && subtle.ConstantTimeCompare(a, b) == 1)
}

// HandshakePayload structure is sent as a JSON blob by the teleport
// proxy to every SSH server who identifies itself as Teleport server
//
// It allows teleport proxies to communicate additional data to server
type HandshakePayload struct {
	// ClientAddr is the IP address of the remote client
	ClientAddr string `json:"clientAddr,omitempty"`
}

// connectionWrapper allows the SSH server to perform custom handshake which
// lets teleport proxy servers to relay a true remote client IP address
// to the SSH server.
//
// (otherwise connection.RemoteAddr (client IP) will always point to a proxy IP
// instead of oa true client IP)
type connectionWrapper struct {
	net.Conn

	// upstreamReader reads from the underlying (wrapped) connection
	upstreamReader io.Reader

	// clientAddr points to the true client address (client is behind
	// a proxy). Keeping this address is the entire point of the
	// connection wrapper.
	clientAddr net.Addr
}

// RemoteAddr returns the behind-the-proxy client address
func (c *connectionWrapper) RemoteAddr() net.Addr {
	return c.clientAddr
}

// Read implements io.Read() part of net.Connection which allows us
// peek at the beginning of SSH handshake (that's why we're wrapping the connection)
func (c *connectionWrapper) Read(b []byte) (int, error) {
	// handshake already took place, forward upstream:
	if c.upstreamReader != nil {
		return c.upstreamReader.Read(b)
	}
	// inspect the client's hello message and see if it's a teleport
	// proxy connecting?
	buff := make([]byte, MaxVersionStringBytes)
	n, err := c.Conn.Read(buff)
	if err != nil {
		log.Error(err)
		return n, err
	}
	// chop off extra unused bytes at the end of the buffer:
	buff = buff[:n]
	var skip = 0

	// are we reading from a Teleport proxy?
	if bytes.HasPrefix(buff, []byte(ProxyHelloSignature)) {
		// the JSON paylaod ends with a binary zero:
		payloadBoundary := bytes.IndexByte(buff, 0x00)
		if payloadBoundary > 0 {
			var hp HandshakePayload
			payload := buff[len(ProxyHelloSignature):payloadBoundary]
			if err = json.Unmarshal(payload, &hp); err != nil {
				log.Error(err)
			} else {
				ca, err := utils.ParseAddr(hp.ClientAddr)
				if err != nil {
					log.Error(err)
				} else {
					// replace proxy's client addr with a real client address
					// we just got from the custom payload:
					c.clientAddr = ca
				}
			}
			skip = payloadBoundary + 1
		}
	}
	c.upstreamReader = io.MultiReader(bytes.NewBuffer(buff[skip:]), c.Conn)
	return c.upstreamReader.Read(b)
}

// wrapConnection takes a network connection, wraps it into connectionWrapper
// object (which overrides Read method) and returns the wrapper.
func wrapConnection(conn net.Conn) net.Conn {
	return &connectionWrapper{
		Conn:       conn,
		clientAddr: conn.RemoteAddr(),
	}
}
