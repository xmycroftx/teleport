package forward

import (
	//"crypto/subtle"
	"fmt"
	//"io"
	"io/ioutil"
	"net"
	//"os"
	//"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/events"
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

	addr string

	alog          events.IAuditLog
	authService   auth.AccessPoint
	reg           *psrv.SessionRegistry
	sessionServer rsession.Service
}

func New(authClient auth.ClientI, addr string) (*Server, error) {
	s := &Server{
		addr:          addr,
		alog:          authClient,
		authService:   authClient,
		sessionServer: authClient,
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
	return s.addr
}

func (s *Server) LogFields(fields map[string]interface{}) log.Fields {
	return log.Fields{
		teleport.Component:       "forwarder",
		teleport.ComponentFields: fields,
	}
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

func (s *Server) Dial(conn net.Conn) error {
	//userChecker := &ssh.CertChecker{
	//	IsUserAuthority: func(p ssh.PublicKey) bool {
	//		return subtle.ConstantTimeCompare(f.userCAChecker.Marshal(), p.Marshal()) == 1
	//	},
	//}

	config := &ssh.ServerConfig{
		//PublicKeyCallback: userChecker.Authenticate,
		NoClientAuth: true,
	}
	nodeSigner, err := readSigner("/Users/rjones/Development/go/src/github.com/gravitational/rusty/teleport/local/one/data/node")
	if err != nil {
		log.Errorf("readsigner: err: %v", err)
		return err
	}
	config.AddHostKey(nodeSigner)

	log.Errorf("trying to make new server conn")

	sconn, chans, reqs, err := ssh.NewServerConn(conn, config)
	if err != nil {
		log.Errorf("newserverconn: err: %v", err)
		return err
	}

	sconn.Permissions = &ssh.Permissions{
		Extensions: map[string]string{utils.CertTeleportUser: "rjones"},
	}

	log.Errorf("new server conn: %v", sconn)

	// global requests
	go func() {
		for newRequest := range reqs {
			go s.handleGlobalRequest(newRequest)
		}
	}()

	// go handle global channel requests
	go func() {
		for newChannel := range chans {
			go s.handleChannel(conn, sconn, newChannel)
		}
	}()

	log.Errorf("Dial done!")

	return nil
}

func (s *Server) handleGlobalRequest(r *ssh.Request) {
	switch r.Type {
	case teleport.KeepAliveReqType:
		s.handleKeepAlive(r)
	default:
		log.Debugf("[SSH] Discarding %q global request: %+v", r.Type, r)
	}
}

func (s *Server) handleChannel(nc net.Conn, sconn *ssh.ServerConn, nch ssh.NewChannel) {
	channelType := nch.ChannelType()
	//if s.proxyMode {
	//	if channelType == "session" { // interactive sessions
	//		ch, requests, err := nch.Accept()
	//		if err != nil {
	//			log.Infof("could not accept channel (%s)", err)
	//		}
	//		go s.handleSessionRequests(sconn, ch, requests)
	//	} else {
	//		nch.Reject(ssh.UnknownChannelType, fmt.Sprintf("unknown channel type: %v", channelType))
	//	}
	//	return
	//}

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
	//case "direct-tcpip": //port forwarding
	//	req, err := sshutils.ParseDirectTCPIPReq(nch.ExtraData())
	//	if err != nil {
	//		log.Errorf("failed to parse request data: %v, err: %v", string(nch.ExtraData()), err)
	//		nch.Reject(ssh.UnknownChannelType, "failed to parse direct-tcpip request")
	//	}
	//	ch, _, err := nch.Accept()
	//	if err != nil {
	//		log.Infof("could not accept channel (%s)", err)
	//	}
	//	go s.handleDirectTCPIPRequest(sconn, ch, req)
	default:
		nch.Reject(ssh.UnknownChannelType, fmt.Sprintf("unknown channel type: %v", channelType))
	}
}

//// handleDirectTCPIPRequest does the port forwarding
//func (s *Server) handleDirectTCPIPRequest(sconn *ssh.ServerConn, ch ssh.Channel, req *sshutils.DirectTCPIPReq) {
//	// ctx holds the connection context and keeps track of the associated resources
//	ctx := psrv.NewServerContext(s, sconn)
//	ctx.IsTestStub = s.isTestStub
//	ctx.AddCloser(ch)
//	defer ctx.Debugf("direct-tcp closed")
//	defer ctx.Close()
//
//	addr := fmt.Sprintf("%v:%d", req.Host, req.Port)
//	ctx.Infof("direct-tcpip channel: %#v to --> %v", req, addr)
//	conn, err := net.Dial("tcp", addr)
//	if err != nil {
//		ctx.Infof("failed connecting to: %v, err: %v", addr, err)
//		return
//	}
//	defer conn.Close()
//	// audit event:
//	s.EmitAuditEvent(events.PortForwardEvent, events.EventFields{
//		events.PortForwardAddr: addr,
//		events.EventLogin:      ctx.Login,
//		events.LocalAddr:       sconn.LocalAddr().String(),
//		events.RemoteAddr:      sconn.RemoteAddr().String(),
//	})
//	wg := &sync.WaitGroup{}
//	wg.Add(1)
//	go func() {
//		defer wg.Done()
//		io.Copy(ch, conn)
//		ch.Close()
//	}()
//	wg.Add(1)
//	go func() {
//		defer wg.Done()
//		io.Copy(conn, ch)
//		conn.Close()
//	}()
//	wg.Wait()
//}

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
	//ctx.Debugf("[SSH] ssh.dispatch(req=%v, wantReply=%v)", req.Type, req.WantReply)
	//// if this SSH server is configured to only proxy, we do not support anything other
	//// than our own custom "subsystems" and environment manipulation
	//if s.proxyMode {
	//	switch req.Type {
	//	case "subsystem":
	//		return s.handleSubsystem(ch, req, ctx)
	//	case "env":
	//		// we currently ignore setting any environment variables via SSH for security purposes
	//		return s.handleEnv(ch, req, ctx)
	//	default:
	//		return trace.BadParameter(
	//			"proxy doesn't support request type '%v'", req.Type)
	//	}
	//}

	switch req.Type {
	//case "exec":
	//	// exec is a remote execution of a program, does not use PTY
	//	return s.handleExec(ch, req, ctx)
	case sshutils.PTYReq:
		// SSH client asked to allocate PTY
		return s.handlePTYReq(ch, req, ctx)
	case "shell":
		// SSH client asked to launch shell, we allocate PTY and start shell session
		ctx.Exec = &psrv.ExecResponse{Ctx: ctx}
		if err := s.reg.OpenSession(ch, req, ctx); err != nil {
			log.Error(err)
			return trace.Wrap(err)
		}
		return nil
	case "env":
		return s.handleEnv(ch, req, ctx)
	//case "subsystem":
	//	// subsystems are SSH subsystems defined in http://tools.ietf.org/html/rfc4254 6.6
	//	// they are in essence SSH session extensions, allowing to implement new SSH commands
	//	return s.handleSubsystem(ch, req, ctx)
	case sshutils.WindowChangeReq:
		return s.handleWinChange(ch, req, ctx)
	case sshutils.AgentReq:
		// This happens when SSH client has agent forwarding enabled, in this case
		// client sends a special request, in return SSH server opens new channel
		// that uses SSH protocol for agent drafted here:
		// https://tools.ietf.org/html/draft-ietf-secsh-agent-02
		// the open ssh proto spec that we implement is here:
		// http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/PROTOCOL.agent
		return s.handleAgentForward(ch, req, ctx)
	default:
		return trace.BadParameter(
			"proxy doesn't support request type '%v'", req.Type)
	}
}

func (s *Server) handleAgentForward(ch ssh.Channel, req *ssh.Request, ctx *psrv.ServerContext) error {
	authChannel, _, err := ctx.Conn.OpenChannel("auth-agent@openssh.com", nil)
	if err != nil {
		return err
	}
	ctx.SetAgent(agent.NewClient(authChannel), authChannel)

	close(ctx.AgentReady)

	//roles, err := s.fetchRoleSet(ctx.TeleportUser, ctx.ClusterName)
	//if err != nil {
	//	return trace.Wrap(err)
	//}
	//if err := roles.CheckAgentForward(ctx.Login); err != nil {
	//	log.Warningf("[SSH:node] denied forward agent %v", err)
	//	return trace.Wrap(err)
	//}
	//systemUser, err := user.Lookup(ctx.Login)
	//if err != nil {
	//	return trace.ConvertSystemError(err)
	//}
	//uid, err := strconv.Atoi(systemUser.Uid)
	//if err != nil {
	//	return trace.Wrap(err)
	//}
	//gid, err := strconv.Atoi(systemUser.Gid)
	//if err != nil {
	//	return trace.Wrap(err)
	//}

	//authChan, _, err := ctx.Conn.OpenChannel("auth-agent@openssh.com", nil)
	//if err != nil {
	//	return trace.Wrap(err)
	//}
	//clientAgent := agent.NewClient(authChan)
	//ctx.SetAgent(clientAgent, authChan)

	//pid := os.Getpid()
	//socketDir, err := ioutil.TempDir(os.TempDir(), "teleport-")
	//if err != nil {
	//	return trace.Wrap(err)
	//}
	//dirCloser := &utils.RemoveDirCloser{Path: socketDir}
	//socketPath := filepath.Join(socketDir, fmt.Sprintf("teleport-%v.socket", pid))
	//if err := os.Chown(socketDir, uid, gid); err != nil {
	//	if err := dirCloser.Close(); err != nil {
	//		log.Warn("failed to remove directory: %v", err)
	//	}
	//	return trace.ConvertSystemError(err)
	//}

	//agentServer := &teleagent.AgentServer{Agent: clientAgent}
	//err = agentServer.ListenUnixSocket(socketPath, uid, gid, 0600)
	//if err != nil {
	//	return trace.Wrap(err)
	//}
	//if req.WantReply {
	//	req.Reply(true, nil)
	//}
	//ctx.SetEnv(teleport.SSHAuthSock, socketPath)
	//ctx.SetEnv(teleport.SSHAgentPID, fmt.Sprintf("%v", pid))
	//ctx.AddCloser(agentServer)
	//ctx.AddCloser(dirCloser)
	//ctx.Debugf("[SSH:node] opened agent channel for teleport user %v and socket %v", ctx.TeleportUser, socketPath)
	//go agentServer.Serve()

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

//func (s *Server) handleSubsystem(ch ssh.Channel, req *ssh.Request, ctx *psrv.ServerContext) error {
//	sb, err := parseSubsystemRequest(s, req)
//	if err != nil {
//		ctx.Warnf("[SSH] %v failed to parse subsystem request: %v", err)
//		return trace.Wrap(err)
//	}
//	ctx.Debugf("[SSH] subsystem request: %v", sb)
//	// starting subsystem is blocking to the client,
//	// while collecting its result and waiting is not blocking
//	if err := sb.start(ctx.Conn, ch, req, ctx); err != nil {
//		ctx.Warnf("[SSH] failed executing request: %v", err)
//		ctx.SendSubsystemResult(trace.Wrap(err))
//		return trace.Wrap(err)
//	}
//	go func() {
//		err := sb.wait()
//		log.Debugf("[SSH] %v finished with result: %v", sb, err)
//		ctx.SendSubsystemResult(trace.Wrap(err))
//	}()
//	return nil
//}

// handleEnv accepts environment variables sent by the client and stores them
// in connection context
func (s *Server) handleEnv(ch ssh.Channel, req *ssh.Request, ctx *psrv.ServerContext) error {
	var e sshutils.EnvReqParams
	if err := ssh.Unmarshal(req.Payload, &e); err != nil {
		ctx.Error(err)
		return trace.Wrap(err, "failed to parse env request")
	}
	ctx.SetEnv(e.Name, e.Value)
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
		term, err = psrv.NewLocalTerminal(ctx)
		if err != nil {
			return trace.Wrap(err)
		}
		ctx.SetTerm(term)
	}
	term.SetWinSize(*params)

	// update the session:
	if err := s.reg.NotifyWinChange(*params, ctx); err != nil {
		log.Error(err)
	}
	return nil
}

//// handleExec is responsible for executing 'exec' SSH requests (i.e. executing
//// a command after making an SSH connection)
////
//// Note: this also handles 'scp' requests because 'scp' is a subset of "exec"
//func (s *Server) handleExec(ch ssh.Channel, req *ssh.Request, ctx *psrv.ServerContext) error {
//	execResponse, err := psrv.ParseExecRequest(req, ctx)
//	if err != nil {
//		ctx.Infof("failed to parse exec request: %v", err)
//		replyError(ch, req, err)
//		return trace.Wrap(err)
//	}
//	if req.WantReply {
//		req.Reply(true, nil)
//	}
//	// a terminal has been previously allocate for this command.
//	// run this inside an interactive session
//	if ctx.GetTerm() != nil {
//		return s.reg.OpenSession(ch, req, ctx)
//	}
//	// ... otherwise, regular execution:
//	result, err := execResponse.Start(ch)
//	if err != nil {
//		ctx.Error(err)
//		replyError(ch, req, err)
//	}
//	if result != nil {
//		ctx.Debugf("%v result collected: %v", execResponse, result)
//		ctx.SendResult(*result)
//	}
//	if err != nil {
//		return trace.Wrap(err)
//	}
//
//	// in case if result is nil and no error, this means that program is
//	// running in the background
//	go func() {
//		result, err = execResponse.Wait()
//		if err != nil {
//			ctx.Errorf("%v wait failed: %v", execResponse, err)
//		}
//		if result != nil {
//			ctx.SendResult(*result)
//		}
//	}()
//	return nil
//}

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

func replyError(ch ssh.Channel, req *ssh.Request, err error) {
	message := []byte(utils.UserMessageFromError(err))
	ch.Stderr().Write(message)
	if req.WantReply {
		req.Reply(false, message)
	}
}

func readSigner(path string) (ssh.Signer, error) {
	privateKey, err := readPrivateKey(path + ".key")
	if err != nil {
		return nil, err
	}

	cert, err := readCertificate(path + ".cert")
	if err != nil {
		return nil, err
	}

	s, err := ssh.NewCertSigner(cert, privateKey)
	if err != nil {
		return nil, err
	}

	return s, nil
}

func readPrivateKey(path string) (ssh.Signer, error) {
	privateBytes, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	private, err := ssh.ParsePrivateKey(privateBytes)
	if err != nil {
		return nil, err
	}

	return private, nil
}

func readCertificate(path string) (*ssh.Certificate, error) {
	publicBytes, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	key, _, _, _, err := ssh.ParseAuthorizedKey(publicBytes)
	if err != nil {
		return nil, err
	}

	sshCert, ok := key.(*ssh.Certificate)
	if !ok {
		return nil, fmt.Errorf("not cert")
	}

	return sshCert, nil
}

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
