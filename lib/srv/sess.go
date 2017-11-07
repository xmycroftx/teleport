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
	"time"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/events"
	"github.com/gravitational/teleport/lib/session"
	"github.com/gravitational/teleport/lib/sshutils"
	"github.com/gravitational/teleport/lib/state"

	"github.com/gravitational/trace"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

const (
	// number of the most recent session writes (what's been written
	// in a terminal) to be instanly replayed to the newly joining
	// parties
	instantReplayLen = 20

	// maxTermSyncErrorCount defines how many subsequent erorrs
	// we should tolerate before giving up trying to sync the
	// term size
	maxTermSyncErrorCount = 5
)

var (
	serverSessions = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "server_interactive_sessions_total",
			Help: "Number of active sessions",
		},
	)
)

func init() {
	// Metrics have to be registered to be exposed:
	prometheus.MustRegister(serverSessions)
}

// SessionRegistry holds a map of all active sessions on a given
// SSH server
type SessionRegistry struct {
	sync.Mutex

	activeSessions map[session.ID]*activeSession
	serverContext  *ServerContext
}

func (s *SessionRegistry) addSession(sess *activeSession) {
	s.Lock()
	defer s.Unlock()
	s.activeSessions[sess.id] = sess
}

func (r *SessionRegistry) Close() {
	r.Lock()
	defer r.Unlock()
	for _, s := range r.activeSessions {
		s.Close()
	}
	log.Debugf("SessionRegistry.Close()")
}

// joinShell either joins an existing session or starts a new shell
func (s *SessionRegistry) openSession(ch ssh.Channel, req *ssh.Request, ctx *SessionContext) error {
	if ctx.activeSession != nil {
		// emit "joined session" event:
		ctx.EmitAuditEvent(events.SessionJoinEvent, events.EventFields{
			events.SessionEventID:  string(ctx.activeSession.id),
			events.EventNamespace:  ctx.ServerContext.Namespace,
			events.EventLogin:      ctx.SystemLogin,
			events.EventUser:       ctx.TeleportUser,
			events.LocalAddr:       ctx.ServerConn.LocalAddr().String(),
			events.RemoteAddr:      ctx.ServerConn.RemoteAddr().String(),
			events.SessionServerID: ctx.ServerContext.ServerID,
		})
		ctx.Infof("[SESSION] joining session: %v", ctx.activeSession.id)
		_, err := ctx.activeSession.join(ch, req, ctx)
		return trace.Wrap(err)
	}
	// session not found? need to create one. start by getting/generating an ID for it
	sid, found := ctx.Environment[sshutils.SessionEnvVar]
	if !found {
		sid = string(session.NewID())
		ctx.Environment[sshutils.SessionEnvVar] = sid
	}
	// This logic allows concurrent request to create a new session
	// to fail, what is ok because we should never have this condition
	sess, err := newSession(session.ID(sid), s, ctx)
	if err != nil {
		return trace.Wrap(err)
	}
	ctx.activeSession = sess
	s.addSession(sess)
	ctx.Infof("[SESSION] new session %v", sid)

	if err := sess.start(ch, ctx); err != nil {
		sess.Close()
		return trace.Wrap(err)
	}
	return nil
}

// leaveSession removes the given party from this session
func (s *SessionRegistry) leaveSession(party *party) error {
	sess := party.s
	s.Lock()
	defer s.Unlock()

	// remove from in-memory representation of the session:
	if err := sess.removeParty(party); err != nil {
		return trace.Wrap(err)
	}

	// emit "session leave" event (party left the session)
	s.serverContext.EmitAuditEvent(events.SessionLeaveEvent, events.EventFields{
		events.SessionEventID:  string(sess.id),
		events.EventUser:       party.user,
		events.SessionServerID: party.serverID,
		events.EventNamespace:  s.serverContext.Namespace,
	})

	// this goroutine runs for a short amount of time only after a session
	// becomes empty (no parties). It allows session to "linger" for a bit
	// allowing parties to reconnect if they lost connection momentarily
	lingerAndDie := func() {
		lingerTTL := sess.GetLingerTTL()
		if lingerTTL > 0 {
			time.Sleep(lingerTTL)
		}
		// not lingering anymore? someone reconnected? cool then... no need
		// to die...
		if !sess.isLingering() {
			log.Infof("[session.registry] session %v becomes active again", sess.id)
			return
		}
		log.Infof("[session.registry] session %v to be garbage collected", sess.id)

		// no more people left? Need to end the session!
		s.Lock()
		delete(s.activeSessions, sess.id)
		s.Unlock()

		// send an event indicating that this session has ended
		s.serverContext.EmitAuditEvent(events.SessionEndEvent, events.EventFields{
			events.SessionEventID: string(sess.id),
			events.EventUser:      party.user,
			events.EventNamespace: s.serverContext.Namespace,
		})
		if err := sess.Close(); err != nil {
			log.Error(err)
		}

		// mark it as inactive in the DB
		if s.serverContext.SessionServer != nil {
			False := false
			s.serverContext.SessionServer.UpdateSession(session.UpdateRequest{
				ID:        sess.id,
				Active:    &False,
				Namespace: s.serverContext.Namespace,
			})
		}
	}
	go lingerAndDie()
	return nil
}

// getParties allows to safely return a list of parties connected to this
// session (as determined by ctx)
func (s *SessionRegistry) getParties(ctx *SessionContext) (parties []*party) {
	sess := ctx.activeSession
	if sess != nil {
		sess.Lock()
		defer sess.Unlock()

		parties = make([]*party, 0, len(sess.parties))
		for _, p := range sess.parties {
			parties = append(parties, p)
		}
	}
	return parties
}

// notifyWinChange is called when an SSH server receives a command notifying
// us that the terminal size has changed
func (s *SessionRegistry) notifyWinChange(params session.TerminalParams, ctx *SessionContext) error {
	if ctx.activeSession == nil {
		log.Debugf("notifyWinChange(): no session found!")
		return nil
	}
	sid := ctx.activeSession.id
	// report this to the event/audit log:
	s.serverContext.EmitAuditEvent(events.ResizeEvent, events.EventFields{
		events.EventNamespace: s.serverContext.Namespace,
		events.SessionEventID: sid,
		events.EventLogin:     ctx.SystemLogin,
		events.EventUser:      ctx.TeleportUser,
		events.TerminalSize:   params.Serialize(),
	})
	err := ctx.activeSession.term.SetWinSize(params)
	if err != nil {
		return trace.Wrap(err)
	}

	// notify all connected parties about the change in real time
	// (if they're capable)
	for _, p := range s.getParties(ctx) {
		p.onWindowChanged(&params)
	}

	go func() {
		err := s.serverContext.SessionServer.UpdateSession(session.UpdateRequest{
			ID:             sid,
			TerminalParams: &params,
			Namespace:      s.serverContext.Namespace,
		})
		if err != nil {
			log.Error(err)
		}
	}()
	return nil
}

func (s *SessionRegistry) broadcastResult(sid session.ID, r ExecResult) error {
	s.Lock()
	defer s.Unlock()

	sess, found := s.findSession(sid)
	if !found {
		return trace.NotFound("session %v not found", sid)
	}
	sess.broadcastResult(r)
	return nil
}

func (s *SessionRegistry) findSession(id session.ID) (*activeSession, bool) {
	sess, found := s.activeSessions[id]
	return sess, found
}

func NewSessionRegistry(serverContext *ServerContext) *SessionRegistry {
	if serverContext.SessionServer == nil {
		panic("need a session server")
	}
	return &SessionRegistry{
		serverContext:  serverContext,
		activeSessions: make(map[session.ID]*activeSession),
	}
}

// activeSession struct describes an active (in progress) SSH session. These sessions
// are managed by 'SessionRegistry' containers which are attached to SSH servers.
type activeSession struct {
	sync.Mutex

	// session ID. unique GUID, this is what people use to "join" sessions
	id session.ID

	// parent session container
	registry *SessionRegistry

	// this writer is used to broadcast terminal I/O to different clients
	writer *multiWriter

	// parties are connected lients/users
	parties map[session.ID]*party

	term Terminal

	// closeC channel is used to kill all goroutines owned
	// by the session
	closeC chan bool

	// Linger TTL means "how long to keep session in memory after the last client
	// disconnected". It's useful to keep it alive for a bit in case the client
	// temporarily dropped the connection and will reconnect (or a browser-based
	// client hits "page refresh").
	lingerTTL time.Duration

	// termSizeC is used to push terminal resize events from SSH "on-size-changed"
	// event handler into "push-to-web-client" loop.
	termSizeC chan []byte

	// login stores the login of the initial session creator
	login string

	closeOnce sync.Once
}

// newSession creates a new session with a given ID within a given context.
func newSession(id session.ID, r *SessionRegistry, ctx *SessionContext) (*activeSession, error) {
	serverSessions.Inc()
	rsess := session.Session{
		ID: id,
		TerminalParams: session.TerminalParams{
			W: teleport.DefaultTerminalWidth,
			H: teleport.DefaultTerminalHeight,
		},
		Login:      ctx.SystemLogin,
		Created:    time.Now().UTC(),
		LastActive: time.Now().UTC(),
		ServerID:   ctx.ServerContext.ServerID,
		Namespace:  ctx.ServerContext.Namespace,
	}
	term := ctx.GetTerm()
	if term != nil {
		winsize, err := term.GetWinSize()
		if err != nil {
			return nil, trace.Wrap(err)
		}
		rsess.TerminalParams.W = int(winsize.Width - 1)
		rsess.TerminalParams.H = int(winsize.Height)
	}
	err := r.serverContext.SessionServer.CreateSession(rsess)
	if err != nil {
		if trace.IsAlreadyExists(err) {
			// if session already exists, make sure they are compatible
			// Login matches existing login
			existing, err := r.serverContext.SessionServer.GetSession(r.serverContext.Namespace, id)
			if err != nil {
				return nil, trace.Wrap(err)
			}
			if existing.Login != rsess.Login {
				return nil, trace.AccessDenied(
					"can't switch users from %v to %v for session %v",
					rsess.Login, existing.Login, id)
			}
		}
		// return nil, trace.Wrap(err)
		// No need to abort. Perhaps the auth server is down?
		// Log the error and continue:
		log.Errorf("failed logging new session: %v", err)
	}

	sess := &activeSession{
		id:        id,
		registry:  r,
		parties:   make(map[session.ID]*party),
		writer:    newMultiWriter(),
		login:     ctx.SystemLogin,
		closeC:    make(chan bool),
		lingerTTL: defaults.SessionRefreshPeriod * 10,
	}
	return sess, nil
}

// PartyForConnection finds an existing party which owns the given connection
func (r *SessionRegistry) PartyForConnection(sconn *ssh.ServerConn) *party {
	r.Lock()
	defer r.Unlock()

	for _, activeSession := range r.activeSessions {
		activeSession.Lock()
		defer activeSession.Unlock()
		parties := activeSession.parties
		for _, party := range parties {
			if party.sconn == sconn {
				return party
			}
		}
	}
	return nil
}

// This goroutine pushes terminal resize events directly into a connected web client
func (p *party) termSizePusher(ch ssh.Channel) {
	var (
		err error
		n   int
	)
	defer func() {
		if err != nil {
			log.Error(err)
		}
	}()

	for err == nil {
		select {
		case newSize := <-p.termSizeC:
			n, err = ch.Write(newSize)
			if err == io.EOF {
				continue
			}
			if err != nil || n == 0 {
				return
			}
		case <-p.closeC:
			return
		}
	}
}

// isLingering returns 'true' if every party has left this session
func (s *activeSession) isLingering() bool {
	s.Lock()
	defer s.Unlock()
	return len(s.parties) == 0
}

// Close ends the active session forcing all clients to disconnect and freeing all resources
func (s *activeSession) Close() error {
	serverSessions.Dec()
	s.closeOnce.Do(func() {
		// closing needs to happen asynchronously because the last client
		// (session writer) will try to close this session, causing a deadlock
		// because of closeOnce
		go func() {
			log.Infof("activeSession.Close(%v)", s.id)
			if s.term != nil {
				s.term.Close()
			}
			close(s.closeC)

			// close all writers in our multi-writer
			s.writer.Lock()
			defer s.writer.Unlock()
			for writerName, writer := range s.writer.writers {
				log.Infof("activitySession.close(writer=%v)", writerName)
				closer, ok := io.Writer(writer).(io.WriteCloser)
				if ok {
					closer.Close()
				}
			}
		}()
	})
	return nil
}

// sessionRecorder implements io.Writer to be plugged into the multi-writer
// associated with every session. It forwards session stream to the audit log
type sessionRecorder struct {
	// alog is the audit log to store session chunks
	alog events.IAuditLog
	// sid defines the session to record
	sid session.ID
	// namespace is session namespace
	namespace string
}

func newSessionRecorder(alog events.IAuditLog, namespace string, sid session.ID) (*sessionRecorder, error) {
	var auditLog events.IAuditLog
	var err error
	if alog == nil {
		auditLog = &events.DiscardAuditLog{}
	} else {
		auditLog, err = state.NewCachingAuditLog(state.CachingAuditLogConfig{
			Namespace: namespace,
			SessionID: string(sid),
			Server:    alog,
		})
		if err != nil {
			return nil, trace.Wrap(err)
		}
	}
	sr := &sessionRecorder{
		alog:      auditLog,
		sid:       sid,
		namespace: namespace,
	}
	return sr, nil
}

// Write takes a chunk and writes it into the audit log
func (r *sessionRecorder) Write(data []byte) (int, error) {
	// we are copying buffer to prevent data corruption:
	// io.Copy allocates single buffer and calls multiple writes in a loop
	// our PostSessionChunk is async and sends reader wrapping buffer
	// to the channel. This can lead to cases when the buffer is re-used
	// and data is corrupted unless we copy the data buffer in the first place
	dataCopy := make([]byte, len(data))
	copy(dataCopy, data)
	// post the chunk of bytes to the audit log:
	chunk := &events.SessionChunk{
		Data: dataCopy,
		Time: time.Now().UTC().UnixNano(),
	}
	if err := r.alog.PostSessionSlice(events.SessionSlice{
		Namespace: r.namespace,
		SessionID: string(r.sid),
		Chunks:    []*events.SessionChunk{chunk},
	}); err != nil {
		log.Error(trace.DebugReport(err))
	}
	return len(data), nil
}

// Close() closes audit log caching forwarder
func (r *sessionRecorder) Close() error {
	return r.alog.Close()
}

// start starts a new interactive process (or a shell) in the current session
func (s *activeSession) start(ch ssh.Channel, ctx *SessionContext) error {
	// create a new "party" (connected client)
	p := newParty(s, ch, ctx)

	// allocate a terminal or take the one previously allocated via a
	// seaprate "allocate TTY" SSH request
	if ctx.GetTerm() != nil {
		s.term = ctx.GetTerm()
		ctx.SetTerm(nil)
	} else {
		var err error
		if s.term, err = NewTerminal(ctx); err != nil {
			ctx.Infof("handleShell failed to create term: %v", err)
			return trace.Wrap(err)
		}
	}

	if err := s.term.Run(); err != nil {
		ctx.Errorf("shell command (%v) failed: %v", ctx.Exec.GetCmd(), err)
		return trace.ConvertSystemError(err)
	}
	if err := s.addParty(p); err != nil {
		return trace.Wrap(err)
	}

	params := s.term.GetTerminalParams()

	// emit "new session created" event:
	s.registry.serverContext.EmitAuditEvent(events.SessionStartEvent, events.EventFields{
		events.EventNamespace:  ctx.ServerContext.Namespace,
		events.SessionEventID:  string(s.id),
		events.SessionServerID: ctx.ServerContext.ServerID,
		events.EventLogin:      ctx.SystemLogin,
		events.EventUser:       ctx.TeleportUser,
		events.LocalAddr:       ctx.ServerConn.LocalAddr().String(),
		events.RemoteAddr:      ctx.ServerConn.RemoteAddr().String(),
		events.TerminalSize:    params.Serialize(),
	})

	// start recording this session
	auditLog := s.registry.serverContext.AuditLog
	if auditLog != nil {
		recorder, err := newSessionRecorder(auditLog, ctx.ServerContext.Namespace, s.id)
		if err != nil {
			return trace.Wrap(err)
		}
		s.writer.addWriter("session-recorder", recorder, true)
	}

	// start asynchronous loop of synchronizing session state with
	// the session server (terminal size and activity)
	go s.pollAndSync()

	// Pipe session to shell and visa-versa capturing input and output
	s.term.AddParty(1)
	go func() {
		// notify terminal about a copy process going on
		defer s.term.AddParty(-1)
		io.Copy(s.writer, s.term.PTY())
		log.Infof("activeSession.io.copy() stopped")
	}()

	// wait for the shell to complete:
	go func() {
		result, err := s.term.Wait()
		if result != nil {
			s.registry.broadcastResult(s.id, *result)
		}
		if err != nil {
			log.Errorf("shell exited with error: %v", err)
		} else {
			// no error? this means the command exited cleanly: no need
			// for this session to "linger" after this.
			s.SetLingerTTL(time.Duration(0))
		}
	}()

	// wait for the session to end before the shell, kill the shell
	go func() {
		<-s.closeC
		s.term.Kill()
	}()

	return nil
}

func (s *activeSession) broadcastResult(r ExecResult) {
	for _, p := range s.parties {
		p.ctx.SendExecResult(r)
	}
}

func (s *activeSession) String() string {
	return fmt.Sprintf("activeSession(id=%v, parties=%v)", s.id, len(s.parties))
}

// removeParty removes the party from two places:
//   1. from in-memory dictionary inside of this session
//   2. from sessin server's storage
func (s *activeSession) removeParty(p *party) error {
	p.ctx.Infof("activeSession.removeParty(%v)", p)

	ns := s.getNamespace()

	// in-memory locked remove:
	lockedRemove := func() {
		s.Lock()
		defer s.Unlock()
		delete(s.parties, p.id)
		s.writer.deleteWriter(string(p.id))
	}
	lockedRemove()

	// remove from the session server (asynchronously)
	storageRemove := func(db session.Service) {
		dbSession, err := db.GetSession(ns, s.id)
		if err != nil {
			log.Error(err)
			return
		}
		if dbSession != nil && dbSession.RemoveParty(p.id) {
			db.UpdateSession(session.UpdateRequest{
				ID:        dbSession.ID,
				Parties:   &dbSession.Parties,
				Namespace: ns,
			})
		}
	}
	if s.registry.serverContext.SessionServer != nil {
		go storageRemove(s.registry.serverContext.SessionServer)
	}
	return nil
}

func (s *activeSession) GetLingerTTL() time.Duration {
	s.Lock()
	defer s.Unlock()
	return s.lingerTTL
}

func (s *activeSession) SetLingerTTL(ttl time.Duration) {
	s.Lock()
	defer s.Unlock()
	s.lingerTTL = ttl
}

func (s *activeSession) getNamespace() string {
	return s.registry.serverContext.Namespace
}

// pollAndSync is a loop inside a goroutite which keeps synchronizing the terminal
// size to what's in the session (so all connected parties have the same terminal size)
// it also updates 'active' field on the session.
func (s *activeSession) pollAndSync() {
	log.Debugf("[activeSession.registry] start pollAndSync()\b")
	defer log.Debugf("[activeSession.registry] end pollAndSync()\n")

	ns := s.getNamespace()

	sessionServer := s.registry.serverContext.SessionServer
	if sessionServer == nil {
		return
	}
	errCount := 0
	sync := func() error {
		sess, err := sessionServer.GetSession(ns, s.id)
		if err != nil || sess == nil {
			return trace.Wrap(err)
		}
		var active = true
		sessionServer.UpdateSession(session.UpdateRequest{
			Namespace: ns,
			ID:        sess.ID,
			Active:    &active,
			Parties:   nil,
		})
		winSize, err := s.term.GetWinSize()
		if err != nil {
			return err
		}
		termSizeChanged := (int(winSize.Width) != sess.TerminalParams.W ||
			int(winSize.Height) != sess.TerminalParams.H)
		if termSizeChanged {
			log.Debugf("terminal has changed from: %v to %v", sess.TerminalParams, winSize)
			err = s.term.SetWinSize(sess.TerminalParams)
		}
		return err
	}

	tick := time.NewTicker(defaults.TerminalSizeRefreshPeriod)
	defer tick.Stop()
	for {
		if err := sync(); err != nil {
			log.Infof("sync term error: %v", err)
			errCount++
			// if the error count keeps going up, this means we're stuck in
			// a bad state: end this goroutine to avoid leaks
			if errCount > maxTermSyncErrorCount {
				return
			}
		} else {
			errCount = 0
		}
		select {
		case <-s.closeC:
			log.Infof("[SSH] terminal sync stopped")
			return
		case <-tick.C:
		}
	}
}

// addParty is called when a new party joins the session.
func (s *activeSession) addParty(p *party) error {
	if s.login != p.login {
		return trace.AccessDenied(
			"can't switch users from %v to %v for session %v",
			s.login, p.login, s.id)
	}

	s.parties[p.id] = p
	// write last chunk (so the newly joined parties won't stare
	// at a blank screen)
	getRecentWrite := func() []byte {
		s.writer.Lock()
		defer s.writer.Unlock()
		data := make([]byte, 0, 1024)
		for i := range s.writer.recentWrites {
			data = append(data, s.writer.recentWrites[i]...)
		}
		return data
	}
	p.Write(getRecentWrite())

	// register this party as one of the session writers
	// (output will go to it)
	s.writer.addWriter(string(p.id), p, true)
	p.ctx.AddCloser(p)
	s.term.AddParty(1)

	// update session on the session server
	storageUpdate := func(db session.Service) {
		dbSession, err := db.GetSession(s.getNamespace(), s.id)
		if err != nil {
			log.Error(err)
			return
		}
		log.Infof("PARTY: %v %v", dbSession, err)
		dbSession.Parties = append(dbSession.Parties, session.Party{
			ID:         p.id,
			User:       p.user,
			ServerID:   p.serverID,
			RemoteAddr: p.site,
			LastActive: p.getLastActive(),
		})
		db.UpdateSession(session.UpdateRequest{
			ID:        dbSession.ID,
			Parties:   &dbSession.Parties,
			Namespace: s.getNamespace(),
		})
	}
	if s.registry.serverContext.SessionServer != nil {
		go storageUpdate(s.registry.serverContext.SessionServer)
	}

	p.ctx.Infof("[SESSION] new party joined: %v", p.String())

	// this goroutine keeps pumping party's input into the session
	go func() {
		defer s.term.AddParty(-1)
		_, err := io.Copy(s.term.PTY(), p)
		p.ctx.Infof("party.io.copy(%v) closed", p.id)
		if err != nil {
			log.Error(err)
		}
	}()
	return nil
}

func (s *activeSession) join(ch ssh.Channel, req *ssh.Request, ctx *SessionContext) (*party, error) {
	p := newParty(s, ch, ctx)
	if err := s.addParty(p); err != nil {
		return nil, trace.Wrap(err)
	}
	return p, nil
}

func newMultiWriter() *multiWriter {
	return &multiWriter{writers: make(map[string]writerWrapper)}
}

type multiWriter struct {
	sync.RWMutex
	writers      map[string]writerWrapper
	recentWrites [][]byte
}

type writerWrapper struct {
	io.WriteCloser
	closeOnError bool
}

func (m *multiWriter) addWriter(id string, w io.WriteCloser, closeOnError bool) {
	m.Lock()
	defer m.Unlock()
	m.writers[id] = writerWrapper{WriteCloser: w, closeOnError: closeOnError}
}

func (m *multiWriter) deleteWriter(id string) {
	m.Lock()
	defer m.Unlock()
	delete(m.writers, id)
}

func (m *multiWriter) lockedAddRecentWrite(p []byte) {
	// make a copy of it (this slice is based on a shared buffer)
	clone := make([]byte, len(p))
	copy(clone, p)
	// add to the list of recent writes
	m.recentWrites = append(m.recentWrites, clone)
	for len(m.recentWrites) > instantReplayLen {
		m.recentWrites = m.recentWrites[1:]
	}
}

// Write multiplexes the input to multiple sub-writers. The entire point
// of multiWriter is to do this
func (m *multiWriter) Write(p []byte) (n int, err error) {
	// lock and make a local copy of available writers:
	getWriters := func() (writers []writerWrapper) {
		m.RLock()
		defer m.RUnlock()
		writers = make([]writerWrapper, 0, len(m.writers))
		for _, w := range m.writers {
			writers = append(writers, w)
		}

		// add the recent write chunk to the "instant replay" buffer
		// of the session, to be replayed to newly joining parties:
		m.lockedAddRecentWrite(p)
		return writers
	}

	// unlock and multiplex the write to all writers:
	for _, w := range getWriters() {
		n, err = w.Write(p)
		if err != nil {
			if w.closeOnError {
				return
			}
			continue
		}
		if n != len(p) {
			err = io.ErrShortWrite
			return
		}
	}
	return len(p), nil
}

func newParty(s *activeSession, ch ssh.Channel, ctx *SessionContext) *party {
	return &party{
		user:      ctx.TeleportUser,
		login:     ctx.SystemLogin,
		serverID:  s.registry.serverContext.ServerID,
		site:      ctx.ServerConn.RemoteAddr().String(),
		id:        session.NewID(),
		ch:        ch,
		ctx:       ctx,
		s:         s,
		sconn:     ctx.ServerConn,
		termSizeC: make(chan []byte, 5),
		closeC:    make(chan bool),
	}
}

type party struct {
	sync.Mutex

	login      string
	user       string
	serverID   string
	site       string
	id         session.ID
	s          *activeSession
	sconn      *ssh.ServerConn
	ch         ssh.Channel
	ctx        *SessionContext
	closeC     chan bool
	termSizeC  chan []byte
	lastActive time.Time
	closeOnce  sync.Once
}

func (p *party) onWindowChanged(params *session.TerminalParams) {
	log.Debugf("party(%s).onWindowChanged(%v)", p.id, params.Serialize())

	p.Lock()
	defer p.Unlock()

	// this prefix will be appended to the end of every socker write going
	// to this party:
	prefix := []byte("\x00" + params.Serialize())
	if p.termSizeC != nil && len(p.termSizeC) == 0 {
		p.termSizeC <- prefix
	}
}

func (p *party) updateActivity() {
	p.Lock()
	defer p.Unlock()
	p.lastActive = time.Now()
}

func (p *party) getLastActive() time.Time {
	p.Lock()
	defer p.Unlock()
	return p.lastActive
}

func (p *party) Read(bytes []byte) (int, error) {
	p.updateActivity()
	return p.ch.Read(bytes)
}

func (p *party) Write(bytes []byte) (int, error) {
	return p.ch.Write(bytes)
}

func (p *party) String() string {
	return fmt.Sprintf("%v party(id=%v)", p.ctx, p.id)
}

func (p *party) Close() (err error) {
	p.closeOnce.Do(func() {
		p.ctx.Infof("party[%v].Close()", p.id)
		if err = p.s.registry.leaveSession(p); err != nil {
			p.ctx.Error(err)
		}
		close(p.closeC)
		close(p.termSizeC)
	})
	return err
}
