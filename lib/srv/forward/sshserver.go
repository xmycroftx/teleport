package forward

import (
	//"crypto/subtle"
	"fmt"
	"io"
	//"io/ioutil"
	"net"
	//"os"
	"sync"
	//"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/events"
	"github.com/gravitational/teleport/lib/services"
	rsession "github.com/gravitational/teleport/lib/session"
	psrv "github.com/gravitational/teleport/lib/srv"
	"github.com/gravitational/teleport/lib/sshutils"
	"github.com/gravitational/teleport/lib/utils"
	"github.com/gravitational/trace"

	log "github.com/sirupsen/logrus"
)

type Server struct {
	hostCAChecker    ssh.PublicKey
	userCAChecker    ssh.PublicKey
	remoteHostSigner ssh.Signer
	remoteHostPort   string

	srcAddr string
	dstAddr string

	agent     agent.Agent
	agentChan ssh.Channel

	remoteClient  *ssh.Client
	remoteSession *ssh.Session

	hostCertificate ssh.Signer

	authClient    auth.ClientI
	alog          events.IAuditLog
	authService   auth.AccessPoint
	reg           *psrv.SessionRegistry
	sessionServer rsession.Service
}

func New(authClient auth.ClientI, a agent.Agent, addr string, hostCertificate ssh.Signer) (*Server, error) {
	s := &Server{
		srcAddr:         addr,
		agent:           a,
		hostCertificate: hostCertificate,
		authClient:      authClient,
		alog:            authClient,
		authService:     authClient,
		sessionServer:   authClient,
	}
	s.reg = psrv.NewSessionRegistry(s)
	return s, nil
}

func (s *Server) ID() string {
	return "0"
}

func (s *Server) GetNamespace() string {
	return "default"
}

func (s *Server) AdvertiseAddr() string {
	return s.dstAddr
}

func (s *Server) Component() string {
	return "forwarder"
}

func (s *Server) EmitAuditEvent(eventType string, fields events.EventFields) {
	log.Debugf("server.EmitAuditEvent(%v)", eventType)
	alog := s.GetAuditLog()
	if alog != nil {
		if err := alog.EmitAuditEvent(eventType, fields); err != nil {
			log.Error(err)
		}
	} else {
		log.Warn("SSH server has no audit log")
	}
}

// PermitUserEnvironment is always false because it's up the the remote host
// to decide if the user environment is ready or not.
func (s *Server) PermitUserEnvironment() bool {
	return false
}

func (s *Server) GetAuditLog() events.IAuditLog {
	return s.alog
}

func (s *Server) GetAuthService() auth.AccessPoint {
	return s.authService
}

func (s *Server) GetSessionServer() rsession.Service {
	return s.sessionServer
}

func getUserCA(authService auth.ClientI) ([][]byte, error) {
	clusterName, err := authService.GetDomainName()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	cid := services.CertAuthID{
		DomainName: clusterName,
		Type:       services.UserCA,
	}
	ca, err := authService.GetCertAuthority(cid, false)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return ca.GetCheckingKeys(), nil
}

//func (s *Server) Dial(conn net.Conn) error {
func (s *Server) Dial(address string) (net.Conn, error) {
	s.dstAddr = address

	config := &ssh.ServerConfig{
		PublicKeyCallback: s.keyAuth,
	}
	config.AddHostKey(s.hostCertificate)

	server, client := net.Pipe()

	go func() {
		var err error

		sconn, chans, reqs, err := ssh.NewServerConn(server, config)
		if err != nil {
			client.Close()
			server.Close()
			log.Errorf("[FORWARD] Unable establish new server connection: %v", err)
			return
		}

		// get a session to the remote node this connection will be forwarded to
		s.remoteClient, s.remoteSession, err = psrv.RemoteSession(s.dstAddr, sconn.User(), s.agent, s.authClient)
		if err != nil {
			log.Errorf("[FORWARD] Unable to build connection to remote host: %v", err)
			rejectChannel(chans, err)
			sconn.Close()
			//client.Close()
			//server.Close()
			return
		}

		// global requests
		go func() {
			for newRequest := range reqs {
				go s.handleGlobalRequest(newRequest)
			}
		}()

		// go handle global channel requests
		go func() {
			for newChannel := range chans {
				go s.handleChannel(sconn, newChannel)
			}
		}()
	}()

	return client, nil
}

func rejectChannel(chans <-chan ssh.NewChannel, err error) {
	for newChannel := range chans {
		err := newChannel.Reject(ssh.ConnectionFailed, err.Error())
		if err != nil {
			log.Errorf("[FORWARD] Unable to reject and close connection.")
		}
		return
	}
}

// keyAuth implements SSH client authentication using public keys and is called
// by the server every time the client connects
func (s *Server) keyAuth(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	certChecker := &ssh.CertChecker{
		IsAuthority: func(p ssh.PublicKey) bool {
			// find cert authority by it's key
			cas, err := s.authService.GetCertAuthorities(services.UserCA, false)
			if err != nil {
				log.Warningf("%v", trace.DebugReport(err))
				return false
			}

			for i := range cas {
				checkers, err := cas[i].Checkers()
				if err != nil {
					log.Warningf("%v", err)
					return false
				}
				for _, checker := range checkers {
					if sshutils.KeysEqual(p, checker) {
						return true
					}
				}
			}

			return false

			//checkingKeys, err := getUserCA(s.client)
			//if err != nil {
			//	return false
			//}

			//for _, keyBytes := range checkingKeys {
			//	key, _, _, _, err := ssh.ParseAuthorizedKey(keyBytes)
			//	if err != nil {
			//		return false
			//	}

			//	caMatch := subtle.ConstantTimeCompare(key.Marshal(), p.Marshal()) == 1
			//	if caMatch {
			//		return true
			//	}
			//}

			//return false
		},
	}

	cid := fmt.Sprintf("conn(%v->%v, user=%v)", conn.RemoteAddr(), conn.LocalAddr(), conn.User())
	fingerprint := fmt.Sprintf("%v %v", key.Type(), sshutils.Fingerprint(key))
	log.Debugf("[SSH] %v auth attempt with key %v", cid, fingerprint)

	logger := log.WithFields(log.Fields{
		"local":       conn.LocalAddr(),
		"remote":      conn.RemoteAddr(),
		"user":        conn.User(),
		"fingerprint": fingerprint,
	})

	cert, ok := key.(*ssh.Certificate)
	log.Debugf("[SSH] %v auth attempt with key %v, %#v", cid, fingerprint, cert)
	if !ok {
		log.Debugf("[SSH] auth attempt, unsupported key type for %v", fingerprint)
		return nil, trace.BadParameter("unsupported key type: %v", fingerprint)
	}
	if len(cert.ValidPrincipals) == 0 {
		log.Debugf("[SSH] need a valid principal for key %v", fingerprint)
		return nil, trace.BadParameter("need a valid principal for key %v", fingerprint)
	}
	if len(cert.KeyId) == 0 {
		log.Debugf("[SSH] need a valid key ID for key %v", fingerprint)
		return nil, trace.BadParameter("need a valid key for key %v", fingerprint)
	}
	teleportUser := cert.KeyId

	logAuditEvent := func(err error) {
		// only failed attempts are logged right now
		if err != nil {
			fields := events.EventFields{
				events.EventUser:          teleportUser,
				events.AuthAttemptSuccess: false,
				events.AuthAttemptErr:     err.Error(),
			}
			log.Warningf("[SSH] failed login attempt %#v", fields)
			s.EmitAuditEvent(events.AuthAttemptEvent, fields)
		}
	}
	permissions, err := certChecker.Authenticate(conn, key)
	if err != nil {
		logAuditEvent(err)
		return nil, trace.Wrap(err)
	}
	if err := certChecker.CheckCert(conn.User(), cert); err != nil {
		logAuditEvent(err)
		return nil, trace.Wrap(err)
	}

	//permissions, err := s.certChecker.Authenticate(conn, key)
	//if err != nil {
	//	logAuditEvent(err)
	//	return nil, trace.Wrap(err)
	//}
	//if err := s.certChecker.CheckCert(conn.User(), cert); err != nil {
	//	logAuditEvent(err)
	//	return nil, trace.Wrap(err)
	//}
	logger.Debugf("[SSH] successfully authenticated")

	// this is the only way I know of to pass valid principal with the
	// connection
	permissions.Extensions[utils.CertTeleportUser] = teleportUser

	clusterName, err := s.checkPermissionToLogin(cert, teleportUser, conn.User())
	if err != nil {
		logger.Errorf("Permission denied: %v", err)
		logAuditEvent(err)
		return nil, trace.Wrap(err)
	}
	permissions.Extensions[utils.CertTeleportClusterName] = clusterName
	permissions.Extensions["cert"] = string(ssh.MarshalAuthorizedKey(cert))

	return permissions, nil
}

func (s *Server) handleGlobalRequest(req *ssh.Request) {
	log.Debugf("[GLOBAL REQUEST] Forwarding %v request", req.Type)

	ok, err := s.remoteSession.SendRequest(req.Type, req.WantReply, req.Payload)
	if err != nil {
		log.Warnf("[GLOBAL REQUEST] Failed to forward %v request: %v", req.Type, err)
		return
	}
	if req.WantReply {
		req.Reply(ok, nil)
	}
}

//func (s *Server) handleChannel(nc net.Conn, sconn *ssh.ServerConn, nch ssh.NewChannel) {
func (s *Server) handleChannel(sconn *ssh.ServerConn, nch ssh.NewChannel) {
	channelType := nch.ChannelType()

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
		go s.handleSessionRequests(sconn, ch, requests)
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
		go s.handleDirectTCPIPRequest(sconn, ch, req)
	default:
		nch.Reject(ssh.UnknownChannelType, fmt.Sprintf("unknown channel type: %v", channelType))
	}
}

// handleDirectTCPIPRequest does the port forwarding
func (s *Server) handleDirectTCPIPRequest(sconn *ssh.ServerConn, ch ssh.Channel, req *sshutils.DirectTCPIPReq) {
	// ctx holds the connection context and keeps track of the associated resources
	ctx := psrv.NewServerContext(s, sconn)
	ctx.RemoteSession = s.remoteSession
	ctx.SetAgent(s.agent, s.agentChan)
	//ctx.IsTestStub = s.isTestStub
	ctx.AddCloser(ch)
	defer ctx.Debugf("direct-tcp closed")
	defer ctx.Close()

	addr := fmt.Sprintf("%v:%d", req.Host, req.Port)
	ctx.Infof("direct-tcpip channel: %#v to --> %v", req, addr)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		ctx.Infof("failed connecting to: %v, err: %v", addr, err)
		return
	}
	defer conn.Close()
	// audit event:
	s.EmitAuditEvent(events.PortForwardEvent, events.EventFields{
		events.PortForwardAddr: addr,
		events.EventLogin:      ctx.Login,
		events.LocalAddr:       sconn.LocalAddr().String(),
		events.RemoteAddr:      sconn.RemoteAddr().String(),
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
func (s *Server) handleSessionRequests(sconn *ssh.ServerConn, ch ssh.Channel, in <-chan *ssh.Request) {
	// ctx holds the connection context and keeps track of the associated resources
	ctx := psrv.NewServerContext(s, sconn)
	ctx.RemoteSession = s.remoteSession
	log.Errorf("ctx.RemoteSession: %v", ctx.RemoteSession)

	// if the proxycommand is where we are forwarding the agent, then we need to
	// keep that in mind (we don't need to wait for the agent to be ready, it's
	// already ready)
	ctx.SetAgent(s.agent, s.agentChan)
	ctx.AgentProxyCommand = true
	//ctx.IsTestStub = s.isTestStub
	ctx.AddCloser(ch)
	defer ctx.Close()

	for {
		// update ctx with the session ID:
		err := ctx.JoinOrCreateSession(s.reg)
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

		select {
		case creq := <-ctx.SubsystemResultC:
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
				replyError(ch, req, err)
				return
			}
			if req.WantReply {
				req.Reply(true, nil)
			}
		case result := <-ctx.Result:
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
func (s *Server) dispatch(ch ssh.Channel, req *ssh.Request, ctx *psrv.ServerContext) error {
	switch req.Type {
	case "exec":
		// exec is a remote execution of a program, does not use PTY
		return s.handleExec(ch, req, ctx)
	case sshutils.PTYReq:
		log.Errorf("pty-req")
		// SSH client asked to allocate PTY
		return s.handlePTYReq(ch, req, ctx)
	case "shell":
		log.Errorf("shell")
		// SSH client asked to launch shell, we allocate PTY and start shell session
		ctx.Exec = &psrv.ExecResponse{Ctx: ctx}
		if err := s.reg.OpenSession(ch, req, ctx); err != nil {
			log.Error(err)
			return trace.Wrap(err)
		}
		return nil
	case "env":
		return s.handleEnv(ch, req, ctx)
	case "subsystem":
		// subsystems are SSH subsystems defined in http://tools.ietf.org/html/rfc4254 6.6
		// they are in essence SSH session extensions, allowing to implement new SSH commands
		return s.handleSubsystem(ch, req, ctx)
	case sshutils.WindowChangeReq:
		return s.handleWinChange(ch, req, ctx)
	case sshutils.AgentReq:
		log.Errorf("auth-agent-req@openssh.com")
		// This happens when SSH client has agent forwarding enabled, in this case
		// client sends a special request, in return SSH server opens new channel
		// that uses SSH protocol for agent drafted here:
		// https://tools.ietf.org/html/draft-ietf-secsh-agent-02
		// the open ssh proto spec that we implement is here:
		// http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/PROTOCOL.agent
		return s.handleAgentForward(ch, req, ctx)
	default:
		return trace.BadParameter(
			"(forward) proxy doesn't support request type '%v'", req.Type)
	}
}

func (s *Server) handleAgentForward(ch ssh.Channel, req *ssh.Request, ctx *psrv.ServerContext) error {
	// check if the role allows agent forwarding
	//roles, err := s.fetchRoleSet(ctx.TeleportUser, ctx.ClusterName)
	roles, err := s.fetchRoleSet(ctx)
	if err != nil {
		return trace.Wrap(err)
	}
	log.Errorf("handleAgentForward: roles: %v", roles)

	if err := roles.CheckAgentForward(ctx.Login); err != nil {
		log.Warningf("[SSH:node] denied forward agent %v", err)
		return trace.Wrap(err)
	}

	//authChannel, _, err := ctx.Conn.OpenChannel("auth-agent@openssh.com", nil)
	//if err != nil {
	//	return err
	//}

	err = agent.ForwardToAgent(s.remoteClient, ctx.GetAgent())
	if err != nil {
		log.Infof("unable to forward requests to agent: %v", err)
	}

	err = agent.RequestAgentForwarding(s.remoteSession)
	if err != nil {
		log.Infof("unable to request agent forwarding: %v", err)
	}

	//log.Debugf("[SSH:forward] Overwriting agent with agent passed in by client")
	//ctx.SetAgent(agent.NewClient(authChannel), authChannel)

	//close(ctx.AgentReady)

	return nil
}

// handleWinChange gets called when 'window chnged' SSH request comes in
func (s *Server) handleWinChange(ch ssh.Channel, req *ssh.Request, ctx *psrv.ServerContext) error {
	params, err := parseWinChange(req)
	if err != nil {
		ctx.Error(err)
		return trace.Wrap(err)
	}
	term := ctx.GetTerm()
	if term != nil {
		err = term.SetWinSize(*params)
		if err != nil {
			ctx.Error(err)
		}
	}
	err = s.reg.NotifyWinChange(*params, ctx)
	if err != nil {
		return trace.Wrap(err)
	}

	return nil
}

func (s *Server) handleSubsystem(ch ssh.Channel, req *ssh.Request, ctx *psrv.ServerContext) error {
	type subsystemRequest struct {
		Name string
	}
	var sr subsystemRequest
	err := ssh.Unmarshal(req.Payload, &sr)
	if err != nil {
		return trace.BadParameter("invalid subsystem request: %v", err)
	}

	subsystem := &remoteSubsystem{
		ctx:          ctx,
		subsytemName: sr.Name,
	}

	err = subsystem.Start(ch)
	if err != nil {
		ctx.Warnf("[REMOTE SUBSYSTEM] Failed to start subsystem: %q: %v", sr.Name, err)
		ctx.SendSubsystemResult(trace.Wrap(err))
		return trace.Wrap(err)
	}

	// in case if result is nil and no error, this means that program is
	// running in the background
	go func() {
		err := subsystem.Wait()
		log.Debugf("[REMOTE SUBSYSTEM] Subsystem %q finished result: %v", sr.Name, err)
		ctx.SendSubsystemResult(err)
	}()

	return nil

	//sb, err := parseSubsystemRequest(s, req)
	//if err != nil {
	//	ctx.Warnf("[SSH] %v failed to parse subsystem request: %v", err)
	//	return trace.Wrap(err)
	//}
	//ctx.Debugf("[SSH] subsystem request: %v", sb)
	//// starting subsystem is blocking to the client,
	//// while collecting its result and waiting is not blocking
	//if err := sb.start(ctx.Conn, ch, req, ctx); err != nil {
	//	ctx.Warnf("[SSH] failed executing request: %v", err)
	//	ctx.SendSubsystemResult(trace.Wrap(err))
	//	return trace.Wrap(err)
	//}
	//go func() {
	//	err := sb.wait()
	//	log.Debugf("[SSH] %v finished with result: %v", sb, err)
	//	ctx.SendSubsystemResult(trace.Wrap(err))
	//}()
	//return nil
}

// handleEnv accepts environment variables sent by the client and stores them
// in connection context
func (s *Server) handleEnv(ch ssh.Channel, req *ssh.Request, ctx *psrv.ServerContext) error {
	var e sshutils.EnvReqParams
	if err := ssh.Unmarshal(req.Payload, &e); err != nil {
		ctx.Error(err)
		return trace.Wrap(err, "failed to parse env request")
	}

	err := s.remoteSession.Setenv(e.Name, e.Value)
	if err != nil {
		log.Debugf("Unable to set environment variable: %v: %v", e.Name, e.Value)
	}

	return nil
}

// handlePTYReq allocates PTY for this SSH connection per client's request
func (s *Server) handlePTYReq(ch ssh.Channel, req *ssh.Request, ctx *psrv.ServerContext) error {
	// parse and get the window size requested
	r, err := psrv.ParsePTYReq(req)
	if err != nil {
		return trace.Wrap(err)
	}

	params, err := rsession.NewTerminalParamsFromUint32(r.W, r.H)
	if err != nil {
		return trace.Wrap(err)
	}
	ctx.Debugf("[SSH] terminal requested of size %v", *params)

	// get an existing terminal or create a new one
	term := ctx.GetTerm()
	if term == nil {
		term, err = psrv.NewTerminal(ctx)
		//term, err = psrv.NewRemoteTerminal(ctx)
		if err != nil {
			return trace.Wrap(err)
		}
		ctx.SetTerm(term)
	}
	term.SetWinSize(*params)
	term.SetTermType(r.Env)

	// update the session:
	if err := s.reg.NotifyWinChange(*params, ctx); err != nil {
		log.Error(err)
	}
	return nil
}

// handleExec is responsible for executing 'exec' SSH requests (i.e. executing
// a command after making an SSH connection)
//
// Note: this also handles 'scp' requests because 'scp' is a subset of "exec"
func (s *Server) handleExec(ch ssh.Channel, req *ssh.Request, ctx *psrv.ServerContext) error {
	execResponse, err := psrv.ParseExecRequest(req, ctx)
	if err != nil {
		ctx.Infof("failed to parse exec request: %v", err)
		replyError(ch, req, err)
		return trace.Wrap(err)
	}
	if req.WantReply {
		req.Reply(true, nil)
	}
	// a terminal has been previously allocate for this command.
	// run this inside an interactive session
	if ctx.GetTerm() != nil {
		return s.reg.OpenSession(ch, req, ctx)
	}
	// ... otherwise, regular execution:
	result, err := execResponse.Start(ch)
	if err != nil {
		ctx.Error(err)
		replyError(ch, req, err)
	}
	if result != nil {
		ctx.Debugf("%v result collected: %v", execResponse, result)
		ctx.SendResult(*result)
	}
	if err != nil {
		return trace.Wrap(err)
	}

	// in case if result is nil and no error, this means that program is
	// running in the background
	go func() {
		result, err = execResponse.Wait()
		if err != nil {
			ctx.Errorf("%v wait failed: %v", execResponse, err)
		}
		if result != nil {
			ctx.SendResult(*result)
		}
	}()
	return nil
}

func replyError(ch ssh.Channel, req *ssh.Request, err error) {
	message := []byte(utils.UserMessageFromError(err))
	ch.Stderr().Write(message)
	if req.WantReply {
		req.Reply(false, message)
	}
}

//func readSigner(path string) (ssh.Signer, error) {
//	privateKey, err := readPrivateKey(path + ".key")
//	if err != nil {
//		return nil, err
//	}
//
//	cert, err := readCertificate(path + ".cert")
//	if err != nil {
//		return nil, err
//	}
//
//	s, err := ssh.NewCertSigner(cert, privateKey)
//	if err != nil {
//		return nil, err
//	}
//
//	return s, nil
//}
//
//func readPrivateKey(path string) (ssh.Signer, error) {
//	privateBytes, err := ioutil.ReadFile(path)
//	if err != nil {
//		return nil, err
//	}
//
//	private, err := ssh.ParsePrivateKey(privateBytes)
//	if err != nil {
//		return nil, err
//	}
//
//	return private, nil
//}
//
//func readCertificate(path string) (*ssh.Certificate, error) {
//	publicBytes, err := ioutil.ReadFile(path)
//	if err != nil {
//		return nil, err
//	}
//
//	key, _, _, _, err := ssh.ParseAuthorizedKey(publicBytes)
//	if err != nil {
//		return nil, err
//	}
//
//	sshCert, ok := key.(*ssh.Certificate)
//	if !ok {
//		return nil, fmt.Errorf("not cert")
//	}
//
//	return sshCert, nil
//}

func parseWinChange(req *ssh.Request) (*rsession.TerminalParams, error) {
	var r sshutils.WinChangeReqParams
	if err := ssh.Unmarshal(req.Payload, &r); err != nil {
		return nil, trace.Wrap(err)
	}
	params, err := rsession.NewTerminalParamsFromUint32(r.W, r.H)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return params, nil
}

// checkPermissionToLogin checks the given certificate (supplied by a connected client)
// to see if this certificate can be allowed to login as user:login pair
func (s *Server) checkPermissionToLogin(cert *ssh.Certificate, teleportUser, osUser string) (string, error) {
	// enumerate all known CAs and see if any of them signed the
	// supplied certificate
	log.Debugf("[HA SSH NODE] checkPermsissionToLogin(%v, %v)", teleportUser, osUser)
	log.Debugf("[HA SSH NODE] ValidPrincipals: %v", cert.ValidPrincipals)
	cas, err := s.authService.GetCertAuthorities(services.UserCA, false)
	if err != nil {
		return "", trace.Wrap(err)
	}
	var ca services.CertAuthority
	for i := range cas {
		checkers, err := cas[i].Checkers()
		if err != nil {
			return "", trace.Wrap(err)
		}
		for _, checker := range checkers {
			if sshutils.KeysEqual(cert.SignatureKey, checker) {
				ca = cas[i]
				break
			}
		}
	}
	// the certificate was signed by unknown authority
	if ca == nil {
		return "", trace.AccessDenied(
			"the certificate for user '%v' is signed by untrusted CA",
			teleportUser)
	}

	domainName, err := s.authService.GetDomainName()
	if err != nil {
		return "", trace.Wrap(err)
	}

	//// for local users, go and check their individual permissions
	//var roles services.RoleSet
	//if domainName == ca.GetClusterName() {
	//	users, err := s.authService.GetUsers()
	//	if err != nil {
	//		return "", nil, trace.Wrap(err)
	//	}
	//	for _, u := range users {
	//		if u.GetName() == teleportUser {
	//			// pass along the traits so we get the substituted roles for this user
	//			roles, err = services.FetchRoles(u.GetRoles(), s.authService, u.GetTraits())
	//			if err != nil {
	//				return "", nil, trace.Wrap(err)
	//			}
	//		}
	//	}
	//} else {
	//	certRoles, err := s.extractRolesFromCert(cert)
	//	if err != nil {
	//		log.Errorf("failed to extract roles from cert: %v", err)
	//		return "", nil, trace.AccessDenied("failed to parse certificate roles")
	//	}
	//	roleNames, err := ca.CombinedMapping().Map(certRoles)
	//	if err != nil {
	//		log.Errorf("failed to map roles %v", err)
	//		return "", nil, trace.AccessDenied("failed to map roles")
	//	}
	//	// pass the principals on the certificate along as the login traits
	//	// to the remote cluster.
	//	traits := map[string][]string{
	//		teleport.TraitLogins: cert.ValidPrincipals,
	//	}
	//	roles, err = services.FetchRoles(roleNames, s.authService, traits)
	//	if err != nil {
	//		return "", nil, trace.Wrap(err)
	//	}
	//}

	//if err := roles.CheckAccessToServer(osUser, s.getInfo()); err != nil {
	//	return "", trace.AccessDenied("user %s@%s is not authorized to login as %v@%s: %v",
	//		teleportUser, ca.GetClusterName(), osUser, domainName, err)
	//}

	return domainName, nil
}

// fetchRoleSet fretches role set for a given user
func (s *Server) fetchRoleSet(ctx *psrv.ServerContext) (services.RoleSet, error) {
	teleportUser := ctx.TeleportUser
	clusterName := ctx.ClusterName
	cert, err := ctx.GetCertificate()
	if err != nil {
		return nil, err
	}

	//localClusterName, err := s.client.GetDomainName()
	//log.Errorf("localClusterName: %v %v", localClusterName, err)
	//if err != nil {
	//	return nil, trace.Wrap(err)
	//}

	//cas, err := s.client.GetCertAuthorities(services.UserCA, false)
	//if err != nil {
	//	return nil, trace.Wrap(err)
	//}

	//var ca services.CertAuthority
	//for i := range cas {
	//	if cas[i].GetClusterName() == clusterName {
	//		ca = cas[i]
	//		break
	//	}
	//}
	//if ca == nil {
	//	return nil, trace.NotFound("could not find certificate authority for cluster %v and user %v", clusterName, teleportUser)
	//}

	cas, err := s.authService.GetCertAuthorities(services.UserCA, false)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	var ca services.CertAuthority
	for i := range cas {
		checkers, err := cas[i].Checkers()
		if err != nil {
			return nil, trace.Wrap(err)
		}
		for _, checker := range checkers {
			if sshutils.KeysEqual(cert.SignatureKey, checker) {
				ca = cas[i]
				break
			}
		}
	}
	// the certificate was signed by unknown authority
	if ca == nil {
		return nil, trace.AccessDenied(
			"the certificate for user '%v' is signed by untrusted CA",
			teleportUser)
	}

	//var roles services.RoleSet
	//if localClusterName == clusterName {
	//	users, err := s.client.GetUsers()
	//	if err != nil {
	//		return nil, trace.Wrap(err)
	//	}
	//	for _, u := range users {
	//		if u.GetName() == teleportUser {
	//			roles, err = services.FetchRoles(u.GetRoles(), s.client, u.GetTraits())
	//			if err != nil {
	//				return nil, trace.Wrap(err)
	//			}
	//		}
	//	}
	//} else {
	//roles, err = services.FetchRoles(ca.GetRoles(), s.client, nil)
	//if err != nil {
	//	return nil, trace.Wrap(err)
	//}
	//}

	// for local users, go and check their individual permissions
	var roles services.RoleSet
	if clusterName == ca.GetClusterName() {
		log.Errorf("here!")
		users, err := s.authService.GetUsers()
		if err != nil {
			return nil, trace.Wrap(err)
		}
		for _, u := range users {
			if u.GetName() == teleportUser {
				// pass along the traits so we get the substituted roles for this user
				roles, err = services.FetchRoles(u.GetRoles(), s.authService, u.GetTraits())
				if err != nil {
					return nil, trace.Wrap(err)
				}
			}
		}
	} else {
		certRoles, err := s.extractRolesFromCert(cert)
		if err != nil {
			log.Errorf("failed to extract roles from cert: %v", err)
			return nil, trace.AccessDenied("failed to parse certificate roles")
		}
		roleNames, err := ca.CombinedMapping().Map(certRoles)
		if err != nil {
			log.Errorf("failed to map roles %v", err)
			return nil, trace.AccessDenied("failed to map roles")
		}
		// pass the principals on the certificate along as the login traits
		// to the remote cluster.
		traits := map[string][]string{
			teleport.TraitLogins: cert.ValidPrincipals,
		}
		log.Errorf("role names: %v", roleNames)
		log.Errorf("traits: %v", traits)
		roles, err = services.FetchRoles(roleNames, s.authService, traits)
		if err != nil {
			return nil, trace.Wrap(err)
		}
	}

	return roles, err
}

// extractRolesFromCert extracts roles from certificate metadata extensions
func (s *Server) extractRolesFromCert(cert *ssh.Certificate) ([]string, error) {
	data, ok := cert.Extensions[teleport.CertExtensionTeleportRoles]
	if !ok {
		// it's ok to not have any roles in the metadata
		return nil, nil
	}
	return services.UnmarshalCertRoles(data)
}
