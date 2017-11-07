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
	"sync"
	"sync/atomic"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/events"
	"github.com/gravitational/teleport/lib/session"
	"github.com/gravitational/teleport/lib/sshutils"
	"github.com/gravitational/teleport/lib/utils"

	"github.com/gravitational/trace"

	log "github.com/sirupsen/logrus"
)

var ctxID int32

// ServerContext holds server specific context such as ID, namespace, and
// references to services.
type ServerContext struct {
	Component string

	ServerConn *ssh.ServerConn

	ServerID              string
	Namespace             string
	AdvertiseAddr         string
	PermitUserEnvironment bool

	AuditLog      events.IAuditLog
	AuthService   auth.AccessPoint
	SessionServer session.Service
}

// EmitAuditEvent logs a given event to the audit log attached to the server
// who owns these sessions.
func (c *ServerContext) EmitAuditEvent(eventType string, fields events.EventFields) {
	log.Debugf("server.EmitAuditEvent(%v)", eventType)

	if c.AuditLog == nil {
		log.Warn("SSH server has no audit log")
	}

	if err := c.AuditLog.EmitAuditEvent(eventType, fields); err != nil {
		log.Error(err)
	}
}

// SessionContext holds session specific context, such as SSH auth agents, PTYs,
// and other resources. SessionContext also holds a ServerContext which can be
// used to access resources on the underlying server. SessionContext can also
// be used to attach resources that should be closed once the session closes.
type SessionContext struct {
	*log.Entry

	// RWMutex is used to protect resources that are concurrently accessed.
	sync.RWMutex

	// closers is a list of io.Closer that will be called when session closes
	// this is handy as sometimes client closes session, in this case resources
	// will be properly closed and deallocated, otherwise they could be kept hanging
	closers []io.Closer

	// activeSession, if there's an active one
	activeSession *activeSession

	// terminal is a PTY if it was requested by the session.
	terminal Terminal

	// Agent provides an interface to the remote SSH agent running on the client.
	agent agent.Agent

	// AgentCh is a SSH channel over which the SSH agent communicates.
	agentChannel ssh.Channel

	// SessionID is a server specific incremental session ID.
	SessionID int

	// Environment holds the list of environment variables passed to the session.
	Environment map[string]string

	// ServerConn is the underlying SSH connection.
	ServerConn *ssh.ServerConn

	// ExecResultCh is a Go channel which will be used to send and receive the
	// result of a "exec" request.
	ExecResultCh chan ExecResult

	// SubsystemResultCh is a Go channel which will be used to send and receive
	// the result of a "subsystem" request.
	SubsystemResultCh chan SubsystemResult

	// TeleportUser is the Teleport user for the current session context.
	TeleportUser string

	// SystemLogin is the *nix system user for the current session context.
	SystemLogin string

	// IsTestStub is set to true by tests.
	IsTestStub bool

	// Exec is the command to be executed within this session context.
	Exec Exec

	// ClusterName is the name of the cluster the user is authenticated with.
	ClusterName string

	// ServerContext holds the server context.
	ServerContext *ServerContext
}

// NewSessionContext configures a new SessionContext and returns it.
func NewSessionContext(serverContext *ServerContext) *SessionContext {
	sessionContext := &SessionContext{
		SessionID:         int(atomic.AddInt32(&ctxID, int32(1))),
		Environment:       make(map[string]string),
		ExecResultCh:      make(chan ExecResult, 10),
		SubsystemResultCh: make(chan SubsystemResult, 10),
		TeleportUser:      serverContext.ServerConn.Permissions.Extensions[utils.CertTeleportUser],
		SystemLogin:       serverContext.ServerConn.User(),
		ClusterName:       serverContext.ServerConn.Permissions.Extensions[utils.CertTeleportClusterName],
		ServerContext:     serverContext,
	}
	sessionContext.Entry = log.WithFields(log.Fields{
		trace.Component: serverContext.Component,
		trace.ComponentFields: log.Fields{
			"local":        serverContext.ServerConn.LocalAddr(),
			"remote":       serverContext.ServerConn.RemoteAddr(),
			"login":        sessionContext.SystemLogin,
			"teleportUser": sessionContext.TeleportUser,
			"id":           sessionContext.SessionID,
		},
	})

	return sessionContext
}

func (c *SessionContext) JoinOrCreateSession(reg *SessionRegistry) error {
	// As SSH conversation progresses, at some point a session will be created and
	// its ID will be added to the environment
	ssid, found := c.Environment[sshutils.SessionEnvVar]
	if !found {
		return nil
	}
	// make sure whatever session is requested is a valid session
	_, err := session.ParseID(ssid)
	if err != nil {
		return trace.BadParameter("invalid session id")
	}

	findSession := func() (*activeSession, bool) {
		reg.Lock()
		defer reg.Unlock()

		return reg.findSession(session.ID(ssid))
	}

	// update ctx with a session ID
	c.activeSession, _ = findSession()
	if c.activeSession == nil {
		log.Debugf("[SSH] will create new session for SSH connection %v", c.ServerConn.RemoteAddr())
	} else {
		log.Debugf("[SSH] will join session %v for SSH connection %v", c.activeSession, c.ServerConn.RemoteAddr())
	}

	return nil
}

// EmitAuditEvent logs a given event to the audit log attached to the server
// who owns these sessions.
func (c *SessionContext) EmitAuditEvent(eventType string, fields events.EventFields) {
	c.ServerContext.EmitAuditEvent(eventType, fields)
}

// AddCloser adds any closer in SessionContext that will be called whenever
// server closes session channel.
func (c *SessionContext) AddCloser(closer io.Closer) {
	c.Lock()
	defer c.Unlock()

	c.closers = append(c.closers, closer)
}

func (c *SessionContext) GetAgent() (agent.Agent, ssh.Channel) {
	c.RLock()
	defer c.RUnlock()

	return c.agent, c.agentChannel
}

func (c *SessionContext) SetAgent(a agent.Agent, ch ssh.Channel) {
	c.Lock()
	defer c.Unlock()

	// if we already had a channel, close it before setting the new one
	if c.agentChannel != nil {
		c.Infof("closing previous agent channel")
		c.agentChannel.Close()
	}

	c.agentChannel = ch
	c.agent = a
}

func (c *SessionContext) GetTerm() Terminal {
	c.RLock()
	defer c.RUnlock()

	return c.terminal
}

func (c *SessionContext) SetTerm(t Terminal) {
	c.Lock()
	defer c.Unlock()

	c.terminal = t
}

// takeClosers returns all resources that should be closed and sets the properties to null
// we do this to avoid calling Close() under lock to avoid potential deadlocks
func (c *SessionContext) takeClosers() []io.Closer {
	// this is done to avoid any operation holding the lock for too long
	c.Lock()
	defer c.Unlock()

	closers := []io.Closer{}
	if c.terminal != nil {
		closers = append(closers, c.terminal)
		c.terminal = nil
	}
	if c.agentChannel != nil {
		closers = append(closers, c.agentChannel)
		c.agentChannel = nil
	}
	closers = append(closers, c.closers...)
	c.closers = nil
	return closers
}

func (c *SessionContext) Close() error {
	return closeAll(c.takeClosers()...)
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

func (c *SessionContext) SendExecResult(r ExecResult) {
	select {
	case c.ExecResultCh <- r:
	default:
		log.Infof("blocked on sending exec result: %v", r)
	}
}

func (c *SessionContext) SendSubsystemResult(s SubsystemResult) {
	select {
	case c.SubsystemResultCh <- s:
	default:
		c.Infof("blocked on sending subsystem result: %v", s)
	}
}

func (c *SessionContext) String() string {
	sconn := c.ServerContext.ServerConn
	return fmt.Sprintf("SessionContext(%v->%v, user=%v, id=%v)", sconn.RemoteAddr(), sconn.LocalAddr(), sconn.User(), c.SessionID)
}
