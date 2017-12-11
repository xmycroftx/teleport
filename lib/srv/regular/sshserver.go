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
*/

// Package regular implements SSH server that supports multiplexing
// tunneling, SSH connections proxying and only supports Key based auth
package regular

import (
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/events"
	"github.com/gravitational/teleport/lib/limiter"
	"github.com/gravitational/teleport/lib/reversetunnel"
	"github.com/gravitational/teleport/lib/services"
	rsession "github.com/gravitational/teleport/lib/session"
	"github.com/gravitational/teleport/lib/srv"
	"github.com/gravitational/teleport/lib/sshutils"
	"github.com/gravitational/teleport/lib/teleagent"
	"github.com/gravitational/teleport/lib/utils"

	"github.com/gravitational/trace"
	"github.com/jonboulle/clockwork"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// Server implements SSH server that uses configuration backend and
// certificate-based authentication
type Server struct {
	sync.Mutex

	namespace string
	addr      utils.NetAddr
	hostname  string

	srv           *sshutils.Server
	hostSigner    ssh.Signer
	shell         string
	authService   auth.AccessPoint
	reg           *srv.SessionRegistry
	sessionServer rsession.Service
	limiter       *limiter.Limiter

	labels      map[string]string                //static server labels
	cmdLabels   map[string]services.CommandLabel //dymanic server labels
	labelsMutex *sync.Mutex

	proxyMode bool
	proxyTun  reversetunnel.Server

	advertiseIP     net.IP
	proxyPublicAddr utils.NetAddr

	// server UUID gets generated once on the first start and never changes
	// usually stored in a file inside the data dir
	uuid string

	// this gets set to true for unit testing
	isTestStub bool

	// sets to true when the server needs to be stopped
	closer *utils.CloseBroadcaster

	// alog points to the AuditLog this server uses to report
	// auditable events
	alog events.IAuditLog

	// clock is a system clock
	clock clockwork.Clock

	// permitUserEnvironment controls if this server will read ~/.tsh/environment
	// before creating a new session.
	permitUserEnvironment bool

	// ciphers is a list of ciphers that the server supports. If omitted,
	// the defaults will be used.
	ciphers []string

	// kexAlgorithms is a list of key exchange (KEX) algorithms that the
	// server supports. If omitted, the defaults will be used.
	kexAlgorithms []string

	// macAlgorithms is a list of message authentication codes (MAC) that
	// the server supports. If omitted the defaults will be used.
	macAlgorithms []string

	// authHandlers are common authorization and authentication related handlers.
	authHandlers *srv.AuthHandlers

	// termHandlers are common terminal related handlers.
	termHandlers *srv.TermHandlers
}

func (s *Server) GetNamespace() string {
	return s.namespace
}

func (s *Server) GetAuditLog() events.IAuditLog {
	return s.alog
}

func (s *Server) GetAccessPoint() auth.AccessPoint {
	return s.authService
}

func (s *Server) GetSessionServer() rsession.Service {
	return s.sessionServer
}

// ServerOption is a functional option passed to the server
type ServerOption func(s *Server) error

// Close closes listening socket and stops accepting connections
func (s *Server) Close() error {
	s.closer.Close()
	s.reg.Close()
	return s.srv.Close()
}

// Start starts server
func (s *Server) Start() error {
	if len(s.cmdLabels) > 0 {
		s.updateLabels()
	}
	go s.heartbeatPresence()
	return s.srv.Start()
}

// Wait waits until server stops
func (s *Server) Wait() {
	s.srv.Wait()
}

// SetShell sets default shell that will be executed for interactive
// sessions
func SetShell(shell string) ServerOption {
	return func(s *Server) error {
		s.shell = shell
		return nil
	}
}

// SetSessionServer represents realtime session registry server
func SetSessionServer(sessionServer rsession.Service) ServerOption {
	return func(s *Server) error {
		s.sessionServer = sessionServer
		return nil
	}
}

// SetProxyMode starts this server in SSH proxying mode
func SetProxyMode(tsrv reversetunnel.Server) ServerOption {
	return func(s *Server) error {
		s.proxyMode = (tsrv != nil)
		s.proxyTun = tsrv
		return nil
	}
}

// SetLabels sets dynamic and static labels that server will report to the
// auth servers
func SetLabels(labels map[string]string,
	cmdLabels services.CommandLabels) ServerOption {
	return func(s *Server) error {
		for name, label := range cmdLabels {
			if label.GetPeriod() < time.Second {
				label.SetPeriod(time.Second)
				cmdLabels[name] = label
				log.Warningf("label period can't be less that 1 second. Period for label '%v' was set to 1 second", name)
			}
		}

		s.labels = labels
		s.cmdLabels = cmdLabels
		return nil
	}
}

// SetLimiter sets rate and connection limiter for this server
func SetLimiter(limiter *limiter.Limiter) ServerOption {
	return func(s *Server) error {
		s.limiter = limiter
		return nil
	}
}

// SetAuditLog assigns an audit log interfaces to this server
func SetAuditLog(alog events.IAuditLog) ServerOption {
	return func(s *Server) error {
		s.alog = alog
		return nil
	}
}

func SetNamespace(namespace string) ServerOption {
	return func(s *Server) error {
		s.namespace = namespace
		return nil
	}
}

// SetPermitUserEnvironment allows you to set the value of permitUserEnvironment.
func SetPermitUserEnvironment(permitUserEnvironment bool) ServerOption {
	return func(s *Server) error {
		s.permitUserEnvironment = permitUserEnvironment
		return nil
	}
}

func SetCiphers(ciphers []string) ServerOption {
	return func(s *Server) error {
		s.ciphers = ciphers
		return nil
	}
}

func SetKEXAlgorithms(kexAlgorithms []string) ServerOption {
	return func(s *Server) error {
		s.kexAlgorithms = kexAlgorithms
		return nil
	}
}

func SetMACAlgorithms(macAlgorithms []string) ServerOption {
	return func(s *Server) error {
		s.macAlgorithms = macAlgorithms
		return nil
	}
}

// New returns an unstarted server
func New(addr utils.NetAddr,
	hostname string,
	signers []ssh.Signer,
	authService auth.AccessPoint,
	dataDir string,
	advertiseIP net.IP,
	proxyPublicAddr utils.NetAddr,
	options ...ServerOption) (*Server, error) {

	// read the host UUID:
	uuid, err := utils.ReadOrMakeHostUUID(dataDir)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	s := &Server{
		addr:            addr,
		authService:     authService,
		hostname:        hostname,
		labelsMutex:     &sync.Mutex{},
		advertiseIP:     advertiseIP,
		proxyPublicAddr: proxyPublicAddr,
		uuid:            uuid,
		closer:          utils.NewCloseBroadcaster(),
		clock:           clockwork.NewRealClock(),
	}
	s.limiter, err = limiter.NewLimiter(limiter.LimiterConfig{})
	if err != nil {
		return nil, trace.Wrap(err)
	}

	for _, o := range options {
		if err := o(s); err != nil {
			return nil, trace.Wrap(err)
		}
	}

	var component string
	if s.proxyMode {
		component = teleport.ComponentProxy
	} else {
		component = teleport.ComponentNode
	}

	s.reg = srv.NewSessionRegistry(s)

	// add in common auth handlers
	s.authHandlers = &srv.AuthHandlers{
		Entry: log.WithFields(log.Fields{
			trace.Component:       component,
			trace.ComponentFields: log.Fields{},
		}),
		Server:      s.getInfo(),
		Component:   component,
		AuditLog:    s.alog,
		AccessPoint: s.authService,
	}

	// common term handlers
	s.termHandlers = &srv.TermHandlers{
		SessionRegistry: s.reg,
	}

	server, err := sshutils.NewServer(
		component,
		addr, s, signers,
		sshutils.AuthMethods{PublicKey: s.authHandlers.UserKeyAuth},
		sshutils.SetLimiter(s.limiter),
		sshutils.SetRequestHandler(s),
		sshutils.SetCiphers(s.ciphers),
		sshutils.SetKEXAlgorithms(s.kexAlgorithms),
		sshutils.SetMACAlgorithms(s.macAlgorithms))
	if err != nil {
		return nil, trace.Wrap(err)
	}
	s.srv = server
	return s, nil
}

func (s *Server) getNamespace() string {
	return services.ProcessNamespace(s.namespace)
}

func (s *Server) Component() string {
	if s.proxyMode {
		return teleport.ComponentProxy
	}
	return teleport.ComponentNode
}

// Addr returns server address
func (s *Server) Addr() string {
	return s.srv.Addr()
}

// ID returns server ID
func (s *Server) ID() string {
	return s.uuid
}

// PermitUserEnvironment returns if ~/.tsh/environment will be read before a
// session is created by this server.
func (s *Server) PermitUserEnvironment() bool {
	return s.permitUserEnvironment
}

func (s *Server) setAdvertiseIP(ip net.IP) {
	s.Lock()
	defer s.Unlock()
	s.advertiseIP = ip
}

func (s *Server) getAdvertiseIP() net.IP {
	s.Lock()
	defer s.Unlock()
	return s.advertiseIP
}

// AdvertiseAddr returns an address this server should be publicly accessible
// as, in "ip:host" form
func (s *Server) AdvertiseAddr() string {
	// set if we have explicit --advertise-ip option
	if s.getAdvertiseIP() == nil {
		return s.addr.Addr
	}
	_, port, _ := net.SplitHostPort(s.addr.Addr)
	return net.JoinHostPort(s.getAdvertiseIP().String(), port)
}

func (s *Server) getInfo() services.Server {
	return &services.ServerV2{
		Kind:    services.KindNode,
		Version: services.V2,
		Metadata: services.Metadata{
			Name:      s.ID(),
			Namespace: s.getNamespace(),
			Labels:    s.labels,
		},
		Spec: services.ServerSpecV2{
			CmdLabels: services.LabelsToV2(s.getCommandLabels()),
			Addr:      s.AdvertiseAddr(),
			Hostname:  s.hostname,
		},
	}
}

// registerServer attempts to register server in the cluster
func (s *Server) registerServer() error {
	server := s.getInfo()
	server.SetTTL(s.clock, defaults.ServerHeartbeatTTL)
	if !s.proxyMode {
		return trace.Wrap(s.authService.UpsertNode(server))
	}
	server.SetPublicAddr(s.proxyPublicAddr.String())
	return trace.Wrap(s.authService.UpsertProxy(server))
}

// heartbeatPresence periodically calls into the auth server to let everyone
// know we're up & alive
func (s *Server) heartbeatPresence() {
	sleepTime := defaults.ServerHeartbeatTTL/2 + utils.RandomDuration(defaults.ServerHeartbeatTTL/10)
	ticker := time.NewTicker(sleepTime)
	defer ticker.Stop()

	for {
		if err := s.registerServer(); err != nil {
			log.Warningf("failed to announce %v presence: %v", s.ID(), err)
		}
		select {
		case <-ticker.C:
			continue
		case <-s.closer.C:
			{
				log.Debugf("server.heartbeatPresence() exited")
				return
			}
		}
	}
}

func (s *Server) updateLabels() {
	for name, label := range s.cmdLabels {
		go s.periodicUpdateLabel(name, label.Clone())
	}
}

func (s *Server) syncUpdateLabels() {
	for name, label := range s.getCommandLabels() {
		s.updateLabel(name, label)
	}
}

func (s *Server) updateLabel(name string, label services.CommandLabel) {
	out, err := exec.Command(label.GetCommand()[0], label.GetCommand()[1:]...).Output()
	if err != nil {
		log.Errorf(err.Error())
		label.SetResult(err.Error() + " output: " + string(out))
	} else {
		label.SetResult(strings.TrimSpace(string(out)))
	}
	s.setCommandLabel(name, label)
}

func (s *Server) periodicUpdateLabel(name string, label services.CommandLabel) {
	for {
		s.updateLabel(name, label)
		time.Sleep(label.GetPeriod())
	}
}

func (s *Server) setCommandLabel(name string, value services.CommandLabel) {
	s.labelsMutex.Lock()
	defer s.labelsMutex.Unlock()
	s.cmdLabels[name] = value
}

func (s *Server) getCommandLabels() map[string]services.CommandLabel {
	s.labelsMutex.Lock()
	defer s.labelsMutex.Unlock()
	out := make(map[string]services.CommandLabel, len(s.cmdLabels))
	for key, val := range s.cmdLabels {
		out[key] = val.Clone()
	}
	return out
}

// serveAgent will build the a sock path for this user and serve an SSH agent on unix socket.
func (s *Server) serveAgent(ctx *srv.ServerContext) error {
	// gather information about user and process. this will be used to set the
	// socket path and permissions
	systemUser, err := user.Lookup(ctx.Identity.Login)
	if err != nil {
		return trace.ConvertSystemError(err)
	}
	uid, err := strconv.Atoi(systemUser.Uid)
	if err != nil {
		return trace.Wrap(err)
	}
	gid, err := strconv.Atoi(systemUser.Gid)
	if err != nil {
		return trace.Wrap(err)
	}
	pid := os.Getpid()

	// build the socket path and set permissions
	socketDir, err := ioutil.TempDir(os.TempDir(), "teleport-")
	if err != nil {
		return trace.Wrap(err)
	}
	dirCloser := &utils.RemoveDirCloser{Path: socketDir}
	socketPath := filepath.Join(socketDir, fmt.Sprintf("teleport-%v.socket", pid))
	if err := os.Chown(socketDir, uid, gid); err != nil {
		if err := dirCloser.Close(); err != nil {
			log.Warn("failed to remove directory: %v", err)
		}
		return trace.ConvertSystemError(err)
	}

	// start an agent on a unix socket
	agentServer := &teleagent.AgentServer{Agent: ctx.GetAgent()}
	err = agentServer.ListenUnixSocket(socketPath, uid, gid, 0600)
	if err != nil {
		return trace.Wrap(err)
	}
	ctx.SetEnv(teleport.SSHAuthSock, socketPath)
	ctx.SetEnv(teleport.SSHAgentPID, fmt.Sprintf("%v", pid))
	ctx.AddCloser(agentServer)
	ctx.AddCloser(dirCloser)
	ctx.Debugf("[SSH:node] opened agent channel for teleport user %v and socket %v", ctx.Identity.TeleportUser, socketPath)
	go agentServer.Serve()

	return nil
}

// EmitAuditEvent logs a given event to the audit log attached to the
// server who owns these sessions
func (s *Server) EmitAuditEvent(eventType string, fields events.EventFields) {
	log.Debugf("server.EmitAuditEvent(%v)", eventType)
	alog := s.alog
	if alog != nil {
		// record the event time with ms precision
		fields[events.EventTime] = s.clock.Now().In(time.UTC).Round(time.Millisecond)
		if err := alog.EmitAuditEvent(eventType, fields); err != nil {
			log.Error(trace.DebugReport(err))
		}
	} else {
		log.Warn("SSH server has no audit log")
	}
}

// HandleRequest processes global out-of-band requests. Global out-of-band
// requests are processed in order (this way the originator knows which
// request we are responding to). If Teleport does not support the request
// type or an error occurs while processing that request Teleport will reply
// req.Reply(false, nil).
//
// For more details: https://tools.ietf.org/html/rfc4254.html#page-4
func (s *Server) HandleRequest(r *ssh.Request) {
	switch r.Type {
	case teleport.KeepAliveReqType:
		s.handleKeepAlive(r)
	case teleport.RecordingProxyReqType:
		s.handleRecordingProxy(r)
	default:
		if r.WantReply {
			r.Reply(false, nil)
		}
		log.Debugf("[SSH] Discarding %q global request: %+v", r.Type, r)
	}
}

// HandleNewChan is called when new channel is opened
func (s *Server) HandleNewChan(nc net.Conn, sconn *ssh.ServerConn, nch ssh.NewChannel) {
	identityContext, err := s.authHandlers.CreateIdentityContext(sconn)
	if err != nil {
		nch.Reject(ssh.Prohibited, fmt.Sprintf("Unable to create identity from connection: %v", err))
		return
	}

	channelType := nch.ChannelType()
	if s.proxyMode {
		if channelType == "session" { // interactive sessions
			ch, requests, err := nch.Accept()
			if err != nil {
				log.Infof("could not accept channel (%s)", err)
			}
			go s.handleSessionRequests(sconn, identityContext, ch, requests)
		} else {
			nch.Reject(ssh.UnknownChannelType, fmt.Sprintf("unknown channel type: %v", channelType))
		}
		return
	}

	switch channelType {
	// a client requested the terminal size to be sent along with every
	// session message (Teleport-specific SSH channel for web-based terminals)
	case "x-teleport-request-resize-events":
		ch, _, _ := nch.Accept()
		go s.handleTerminalResize(sconn, ch)
	case "session": // interactive sessions
		ch, requests, err := nch.Accept()
		if err != nil {
			log.Infof("could not accept channel (%s)", err)
		}
		go s.handleSessionRequests(sconn, identityContext, ch, requests)
	case "direct-tcpip": //port forwarding
		req, err := sshutils.ParseDirectTCPIPReq(nch.ExtraData())
		if err != nil {
			log.Errorf("failed to parse request data: %v, err: %v", string(nch.ExtraData()), err)
			nch.Reject(ssh.UnknownChannelType, "failed to parse direct-tcpip request")
		}
		ch, _, err := nch.Accept()
		if err != nil {
			log.Infof("could not accept channel (%s)", err)
		}
		go s.handleDirectTCPIPRequest(sconn, identityContext, ch, req)
	default:
		nch.Reject(ssh.UnknownChannelType, fmt.Sprintf("unknown channel type: %v", channelType))
	}
}

// handleDirectTCPIPRequest does the port forwarding
func (s *Server) handleDirectTCPIPRequest(sconn *ssh.ServerConn, identityContext srv.IdentityContext, ch ssh.Channel, req *sshutils.DirectTCPIPReq) {
	// ctx holds the connection context and keeps track of the associated resources
	ctx := srv.NewServerContext(s, sconn, identityContext)
	ctx.IsTestStub = s.isTestStub
	ctx.AddCloser(ch)
	defer ctx.Debugf("direct-tcp closed")
	defer ctx.Close()

	srcAddr := fmt.Sprintf("%v:%d", req.Orig, req.OrigPort)
	dstAddr := fmt.Sprintf("%v:%d", req.Host, req.Port)

	// check if the role allows port forwarding for this user
	err := s.authHandlers.CheckPortForward(dstAddr, ctx)
	if err != nil {
		ch.Stderr().Write([]byte(err.Error()))
		return
	}

	ctx.Debugf("Opening direct-tcpip channel from %v to %v", srcAddr, dstAddr)

	conn, err := net.Dial("tcp", dstAddr)
	if err != nil {
		ctx.Infof("Failed to connect to: %v: %v", dstAddr, err)
		return
	}
	defer conn.Close()

	// audit event:
	s.EmitAuditEvent(events.PortForwardEvent, events.EventFields{
		events.PortForwardAddr:    dstAddr,
		events.PortForwardSuccess: true,
		events.EventLogin:         ctx.Identity.Login,
		events.LocalAddr:          sconn.LocalAddr().String(),
		events.RemoteAddr:         sconn.RemoteAddr().String(),
	})
	wg := &sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		io.Copy(ch, conn)
		ch.Close()
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		io.Copy(conn, ch)
		conn.Close()
	}()
	wg.Wait()
}

// handleTerminalResize is called by the web proxy via its SSH connection.
// when a web browser connects to the web API, the web proxy asks us,
// by creating this new SSH channel, to start injecting the terminal size
// into every SSH write back to it.
//
// this is the only way to make web-based terminal UI not break apart
// when window changes its size
func (s *Server) handleTerminalResize(sconn *ssh.ServerConn, ch ssh.Channel) {
	err := s.reg.PushTermSizeToParty(sconn, ch)
	if err != nil {
		log.Warnf("Unable to push terminal size to party: %v", err)
	}
}

// handleSessionRequests handles out of band session requests once the session channel has been created
// this function's loop handles all the "exec", "subsystem" and "shell" requests.
func (s *Server) handleSessionRequests(sconn *ssh.ServerConn, identityContext srv.IdentityContext, ch ssh.Channel, in <-chan *ssh.Request) {
	// ctx holds the connection context and keeps track of the associated resources
	ctx := srv.NewServerContext(s, sconn, identityContext)
	ctx.IsTestStub = s.isTestStub
	ctx.AddCloser(ch)
	defer ctx.Close()

	for {
		// update ctx with the session ID:
		if !s.proxyMode {
			err := ctx.CreateOrJoinSession(s.reg)
			if err != nil {
				errorMessage := fmt.Sprintf("unable to update context: %v", err)
				ctx.Errorf("[SSH] %v", errorMessage)

				// write the error to channel and close it
				ch.Stderr().Write([]byte(errorMessage))
				_, err := ch.SendRequest("exit-status", false, ssh.Marshal(struct{ C uint32 }{C: teleport.RemoteCommandFailure}))
				if err != nil {
					ctx.Errorf("[SSH] failed to send exit status %v", errorMessage)
				}
				return
			}
		}
		select {
		case creq := <-ctx.SubsystemResultCh:
			// this means that subsystem has finished executing and
			// want us to close session and the channel
			ctx.Debugf("[SSH] close session request: %v", creq.Err)
			return
		case req := <-in:
			if req == nil {
				// this will happen when the client closes/drops the connection
				ctx.Debugf("[SSH] client %v disconnected", sconn.RemoteAddr())
				return
			}
			if err := s.dispatch(ch, req, ctx); err != nil {
				s.replyError(ch, req, err)
				return
			}
			if req.WantReply {
				req.Reply(true, nil)
			}
		case result := <-ctx.ExecResultCh:
			ctx.Debugf("[SSH] ctx.result = %v", result)
			// this means that exec process has finished and delivered the execution result,
			// we send it back and close the session
			_, err := ch.SendRequest("exit-status", false, ssh.Marshal(struct{ C uint32 }{C: uint32(result.Code)}))
			if err != nil {
				ctx.Infof("[SSH] %v failed to send exit status: %v", result.Command, err)
			}
			return
		}
	}
}

// dispatch receives an SSH request for a subsystem and disptaches the request to the
// appropriate subsystem implementation
func (s *Server) dispatch(ch ssh.Channel, req *ssh.Request, ctx *srv.ServerContext) error {
	ctx.Debugf("[SSH] ssh.dispatch(req=%v, wantReply=%v)", req.Type, req.WantReply)
	// if this SSH server is configured to only proxy, we do not support anything other
	// than our own custom "subsystems" and environment manipulation
	if s.proxyMode {
		switch req.Type {
		case sshutils.SubsystemRequest:
			return s.handleSubsystem(ch, req, ctx)
		case sshutils.EnvRequest:
			// we currently ignore setting any environment variables via SSH for security purposes
			return s.handleEnv(ch, req, ctx)
		case sshutils.AgentForwardRequest:
			// process agent forwarding, but we will only forward agent to proxy in
			// recording proxy mode.
			err := s.handleAgentForwardProxy(req, ctx)
			if err != nil {
				log.Debug(err)
			}
			return nil
		default:
			return trace.BadParameter(
				"(%v) proxy doesn't support request type '%v'", s.Component(), req.Type)
		}
	}

	switch req.Type {
	case sshutils.ExecRequest:
		return s.termHandlers.HandleExec(ch, req, ctx)
	case sshutils.PTYRequest:
		return s.termHandlers.HandlePTYReq(ch, req, ctx)
	case sshutils.ShellRequest:
		return s.termHandlers.HandleShell(ch, req, ctx)
	case sshutils.WindowChangeRequest:
		return s.termHandlers.HandleWinChange(ch, req, ctx)
	case sshutils.EnvRequest:
		return s.handleEnv(ch, req, ctx)
	case sshutils.SubsystemRequest:
		// subsystems are SSH subsystems defined in http://tools.ietf.org/html/rfc4254 6.6
		// they are in essence SSH session extensions, allowing to implement new SSH commands
		return s.handleSubsystem(ch, req, ctx)
	case sshutils.AgentForwardRequest:
		// This happens when SSH client has agent forwarding enabled, in this case
		// client sends a special request, in return SSH server opens new channel
		// that uses SSH protocol for agent drafted here:
		// https://tools.ietf.org/html/draft-ietf-secsh-agent-02
		// the open ssh proto spec that we implement is here:
		// http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/PROTOCOL.agent

		// to maintain interoperability with OpenSSH, agent forwarding requests
		// should never fail, all errors should be logged and we should continue
		// processing requests.
		err := s.handleAgentForwardNode(req, ctx)
		if err != nil {
			log.Debug(err)
		}
		return nil
	default:
		return trace.BadParameter(
			"%v doesn't support request type '%v'", s.Component(), req.Type)
	}
}

// handleAgentForwardNode will create a unix socket and serve the agent running
// on the client on it.
func (s *Server) handleAgentForwardNode(req *ssh.Request, ctx *srv.ServerContext) error {
	// check if the user's RBAC role allows agent forwarding
	err := s.authHandlers.CheckAgentForward(ctx)
	if err != nil {
		return trace.Wrap(err)
	}

	// open a channel to the client where the client will serve an agent
	authChannel, _, err := ctx.Conn.OpenChannel(sshutils.AuthAgentRequest, nil)
	if err != nil {
		return trace.Wrap(err)
	}

	// save the agent in the context so it can be used later
	ctx.SetAgent(agent.NewClient(authChannel), authChannel)

	// serve an agent on a unix socket on this node
	err = s.serveAgent(ctx)
	if err != nil {
		return trace.Wrap(err)
	}

	return nil
}

// handleAgentForwardProxy will forward the clients agent to the proxy (when
// the proxy is running in recording mode). When running in normal mode, this
// request will do nothing. To maintain interoperability, agent forwarding
// requests should never fail, all errors should be logged and we should
// continue processing requests.
func (s *Server) handleAgentForwardProxy(req *ssh.Request, ctx *srv.ServerContext) error {
	// we only support agent forwarding at the proxy when the proxy is in recording mode
	clusterConfig, err := s.GetAccessPoint().GetClusterConfig()
	if err != nil {
		return trace.Wrap(err)
	}
	if clusterConfig.GetSessionRecording() != services.RecordAtProxy {
		return trace.BadParameter("agent forwarding to proxy only supported in recording mode")
	}

	// check if the user's RBAC role allows agent forwarding
	err = s.authHandlers.CheckAgentForward(ctx)
	if err != nil {
		return trace.Wrap(err)
	}

	// open a channel to the client where the client will serve an agent
	authChannel, _, err := ctx.Conn.OpenChannel(sshutils.AuthAgentRequest, nil)
	if err != nil {
		return trace.Wrap(err)
	}

	// we save the agent so it can be used when we make a proxy subsystem request
	// later and use it to build a remote connection to the target node.
	ctx.SetAgent(agent.NewClient(authChannel), authChannel)

	return nil
}

func (s *Server) handleSubsystem(ch ssh.Channel, req *ssh.Request, ctx *srv.ServerContext) error {
	sb, err := s.parseSubsystemRequest(req, ctx)
	if err != nil {
		ctx.Warnf("[SSH] %v failed to parse subsystem request: %v", err)
		return trace.Wrap(err)
	}
	ctx.Debugf("[SSH] subsystem request: %v", sb)
	// starting subsystem is blocking to the client,
	// while collecting its result and waiting is not blocking
	if err := sb.Start(ctx.Conn, ch, req, ctx); err != nil {
		ctx.Warnf("[SSH] failed executing request: %v", err)
		ctx.SendSubsystemResult(srv.SubsystemResult{Err: trace.Wrap(err)})
		return trace.Wrap(err)
	}
	go func() {
		err := sb.Wait()
		log.Debugf("[SSH] %v finished with result: %v", sb, err)
		ctx.SendSubsystemResult(srv.SubsystemResult{Err: trace.Wrap(err)})
	}()
	return nil
}

// handleEnv accepts environment variables sent by the client and stores them
// in connection context
func (s *Server) handleEnv(ch ssh.Channel, req *ssh.Request, ctx *srv.ServerContext) error {
	var e sshutils.EnvReqParams
	if err := ssh.Unmarshal(req.Payload, &e); err != nil {
		ctx.Error(err)
		return trace.Wrap(err, "failed to parse env request")
	}
	ctx.SetEnv(e.Name, e.Value)
	return nil
}

// handleKeepAlive accepts and replies to keepalive@openssh.com requests.
func (s *Server) handleKeepAlive(req *ssh.Request) {
	log.Debugf("[KEEP ALIVE] Received %q: WantReply: %v", req.Type, req.WantReply)

	// only reply if the sender actually wants a response
	if req.WantReply {
		err := req.Reply(true, nil)
		if err != nil {
			log.Warnf("[KEEP ALIVE] Unable to reply to %q request: %v", req.Type, err)
			return
		}
	}

	log.Debugf("[KEEP ALIVE] Replied to %q", req.Type)
}

// handleRecordingProxy responds to global out-of-band with a bool which
// indicates if it is in recording mode or not.
func (s *Server) handleRecordingProxy(req *ssh.Request) {
	var recordingProxy bool

	log.Debugf("Global request (%v, %v) received", req.Type, req.WantReply)

	if req.WantReply {
		// get the cluster config, if we can't get it, reply false
		clusterConfig, err := s.authService.GetClusterConfig()
		if err != nil {
			err := req.Reply(false, nil)
			if err != nil {
				log.Warnf("Unable to respond to global request (%v, %v): %v", req.Type, req.WantReply, err)
			}
			return
		}

		// reply true that we were able to process the message and reply with a
		// bool if we are in recording mode or not
		recordingProxy = clusterConfig.GetSessionRecording() == services.RecordAtProxy
		err = req.Reply(true, []byte(strconv.FormatBool(recordingProxy)))
		if err != nil {
			log.Warnf("Unable to respond to global request (%v, %v): %v: %v", req.Type, req.WantReply, recordingProxy, err)
			return
		}
	}

	log.Debugf("Replied to global request (%v, %v): %v", req.Type, req.WantReply, recordingProxy)
}

func (s *Server) replyError(ch ssh.Channel, req *ssh.Request, err error) {
	log.Error(err)
	message := []byte(utils.UserMessageFromError(err))
	ch.Stderr().Write(message)
	if req.WantReply {
		req.Reply(false, message)
	}
}

func (s *Server) parseSubsystemRequest(req *ssh.Request, ctx *srv.ServerContext) (srv.Subsystem, error) {
	var r sshutils.SubsystemReq
	if err := ssh.Unmarshal(req.Payload, &r); err != nil {
		return nil, fmt.Errorf("failed to parse subsystem request, error: %v", err)
	}
	if s.proxyMode && strings.HasPrefix(r.Name, "proxy:") {
		return parseProxySubsys(r.Name, s, ctx)
	}
	if s.proxyMode && strings.HasPrefix(r.Name, "proxysites") {
		return parseProxySitesSubsys(r.Name, s)
	}
	return nil, trace.BadParameter("unrecognized subsystem: %v", r.Name)
}
