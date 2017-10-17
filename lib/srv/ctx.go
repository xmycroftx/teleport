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

package srv

import (
	"fmt"
	"io"
	//"os/exec"
	"sync"
	"sync/atomic"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/events"
	rsession "github.com/gravitational/teleport/lib/session"
	"github.com/gravitational/teleport/lib/sshutils"
	"github.com/gravitational/teleport/lib/utils"
	"github.com/gravitational/trace"

	log "github.com/sirupsen/logrus"
)

var ctxID int32

// subsystemResult is a result of execution of the subsystem
type SubsystemResult struct {
	Err error
}

type Server interface {
	ID() string
	GetNamespace() string
	AdvertiseAddr() string

	Component() string
	PermitUserEnvironment() bool

	EmitAuditEvent(string, events.EventFields)

	GetAuditLog() events.IAuditLog
	GetAuthService() auth.AccessPoint
	GetSessionServer() rsession.Service
}

// ctx holds session specific context, such as SSH auth agents
// PTYs, and other resources. ctx can be used to attach resources
// that should be closed once the session closes.
type ServerContext struct {
	*log.Entry

	// env is a list of environment variables passed to the session
	env map[string]string

	// srv is a pointer to the server holding the context
	srv Server

	// server specific incremental session id
	id int

	// SSH connection
	Conn *ssh.ServerConn

	certificate string

	sync.RWMutex

	// term holds PTY if it was requested by the session
	term Terminal

	AgentProxyCommand bool

	// agent is a client to remote SSH agent
	agent agent.Agent

	// agentCh is SSH channel using SSH agent protocol
	agentCh ssh.Channel

	RemoteSession *ssh.Session

	//AgentReady chan bool

	// result channel will be used by remote executions
	// that are processed in separate process, once the result is collected
	// they would send the result to this channel
	Result chan ExecResult

	// close used by channel operations asking to close the session
	SubsystemResultC chan SubsystemResult

	// closers is a list of io.Closer that will be called when session closes
	// this is handy as sometimes client closes session, in this case resources
	// will be properly closed and deallocated, otherwise they could be kept hanging
	closers []io.Closer

	// teleportUser is a teleport user that was used to log in
	TeleportUser string

	// login is operating system user login chosen by the user
	Login string

	// isTestStub is set to True by tests
	IsTestStub bool

	// session, if there's an active one
	session *session

	// full command asked to be executed in this context
	//Exec *ExecResponse
	Exec Exec

	// clusterName is the name of the cluster current user
	// is authenticated with
	ClusterName string
}

func (c *ServerContext) GetCertificate() (*ssh.Certificate, error) {
	k, _, _, _, err := ssh.ParseAuthorizedKey([]byte(c.certificate))
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return k.(*ssh.Certificate), nil
}

func (c *ServerContext) JoinOrCreateSession(reg *SessionRegistry) error {
	// As SSH conversation progresses, at some point a session will be created and
	// its ID will be added to the environment
	ssid, found := c.GetEnv(sshutils.SessionEnvVar)
	if !found {
		return nil
	}
	// make sure whatever session is requested is a valid session
	_, err := rsession.ParseID(ssid)
	if err != nil {
		return trace.BadParameter("invalid session id")
	}

	findSession := func() (*session, bool) {
		reg.Lock()
		defer reg.Unlock()
		return reg.findSession(rsession.ID(ssid))
	}

	// update ctx with a session ID
	c.session, _ = findSession()
	if c.session == nil {
		log.Debugf("[SSH] will create new session for SSH connection %v", c.Conn.RemoteAddr())
	} else {
		log.Debugf("[SSH] will join session %v for SSH connection %v", c.session, c.Conn.RemoteAddr())
	}

	return nil
}

// addCloser adds any closer in ctx that will be called
// whenever server closes session channel
func (c *ServerContext) AddCloser(closer io.Closer) {
	c.Lock()
	defer c.Unlock()
	c.closers = append(c.closers, closer)
}

func (c *ServerContext) GetAgent() agent.Agent {
	c.RLock()
	defer c.RUnlock()
	return c.agent
}

func (c *ServerContext) GetAgentChannel() ssh.Channel {
	c.RLock()
	defer c.RUnlock()
	return c.agentCh
}

func (c *ServerContext) SetAgent(a agent.Agent, ch ssh.Channel) {
	c.Lock()
	defer c.Unlock()
	if c.agentCh != nil {
		c.Infof("closing previous agent channel")
		c.agentCh.Close()
	}
	c.agentCh = ch
	c.agent = a
}

func (c *ServerContext) GetTerm() Terminal {
	c.RLock()
	defer c.RUnlock()
	return c.term
}

func (c *ServerContext) SetTerm(t Terminal) {
	c.Lock()
	defer c.Unlock()
	c.term = t
}

// takeClosers returns all resources that should be closed and sets the properties to null
// we do this to avoid calling Close() under lock to avoid potential deadlocks
func (c *ServerContext) takeClosers() []io.Closer {
	// this is done to avoid any operation holding the lock for too long
	c.Lock()
	defer c.Unlock()
	closers := []io.Closer{}
	if c.term != nil {
		closers = append(closers, c.term)
		c.term = nil
	}
	if c.agentCh != nil {
		closers = append(closers, c.agentCh)
		c.agentCh = nil
	}
	closers = append(closers, c.closers...)
	c.closers = nil
	return closers
}

func (c *ServerContext) Close() error {
	return closeAll(c.takeClosers()...)
}

func (c *ServerContext) SendResult(r ExecResult) {
	select {
	case c.Result <- r:
	default:
		log.Infof("blocked on sending exec result %v", r)
	}
}

func (c *ServerContext) SendSubsystemResult(err error) {
	select {
	case c.SubsystemResultC <- SubsystemResult{Err: err}:
	default:
		c.Infof("blocked on sending close request")
	}
}

func (c *ServerContext) String() string {
	return fmt.Sprintf("sess(%v->%v, user=%v, id=%v)", c.Conn.RemoteAddr(), c.Conn.LocalAddr(), c.Conn.User(), c.id)
}

func (c *ServerContext) SetEnv(key, val string) {
	c.Debugf("SetEnv(%v=%v)", key, val)
	c.env[key] = val
}

func (c *ServerContext) GetEnv(key string) (string, bool) {
	val, ok := c.env[key]
	return val, ok
}

func NewServerContext(srv Server, conn *ssh.ServerConn) *ServerContext {
	log.Errorf("NewServerContext: %v", conn.Permissions.Extensions[utils.CertTeleportClusterName])
	ctx := &ServerContext{
		env:              make(map[string]string),
		Conn:             conn,
		id:               int(atomic.AddInt32(&ctxID, int32(1))),
		Result:           make(chan ExecResult, 10),
		SubsystemResultC: make(chan SubsystemResult, 10),
		srv:              srv,
		TeleportUser:     conn.Permissions.Extensions[utils.CertTeleportUser],
		ClusterName:      conn.Permissions.Extensions[utils.CertTeleportClusterName],
		certificate:      conn.Permissions.Extensions["cert"],
		Login:            conn.User(),
		//AgentReady:       make(chan bool),
	}

	ctx.Entry = log.WithFields(log.Fields{
		trace.Component: srv.Component(),
		trace.ComponentFields: log.Fields{
			"local":        conn.LocalAddr(),
			"remote":       conn.RemoteAddr(),
			"login":        ctx.Login,
			"teleportUser": ctx.TeleportUser,
			"id":           ctx.id,
		},
	})
	return ctx
}

func closeAll(closers ...io.Closer) error {
	var err error
	for _, cl := range closers {
		if cl == nil {
			continue
		}
		if e := cl.Close(); e != nil {
			err = e
		}
	}
	return err
}

type closerFunc func() error

func (f closerFunc) Close() error {
	return f()
}
