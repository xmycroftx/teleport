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
	"io"
	"os"
	"os/exec"
	"sync"
	"syscall"

	"golang.org/x/crypto/ssh"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/lib/services"
	rsession "github.com/gravitational/teleport/lib/session"
	"github.com/gravitational/teleport/lib/sshutils"

	"github.com/gravitational/trace"
	"github.com/kr/pty"
	"github.com/moby/moby/pkg/term"
	log "github.com/sirupsen/logrus"
)

// Terminal defines an interface of handy functions for managing a (local or
// remote) PTY, such as resizing windows, executing commands with a PTY, and
// cleaning up.
type Terminal interface {
	// AddParty adds another participant to this terminal. We will keep the
	// Terminal open until all participants have left.
	AddParty(delta int)

	// Run will run the terminal.
	Run() error

	// Wait will block until the terminal is complete.
	Wait() (*ExecResult, error)

	// Kill will force kill the terminal.
	Kill() error

	// PTY returns the PTY backing the terminal.
	PTY() io.ReadWriter

	// TTY returns the TTY backing the terminal.
	TTY() *os.File

	// Close will free resources associated with the terminal.
	Close() error

	// GetWinSize returns the window size of the terminal.
	GetWinSize() (*term.Winsize, error)

	// SetWinSize sets the window size of the terminal.
	SetWinSize(params rsession.TerminalParams) error

	// GetTerminalParams is a fast call to get cached terminal parameters
	// and avoid extra system call.
	GetTerminalParams() rsession.TerminalParams

	// SetTermType sets the terminal type from "pty-req"
	SetTermType(string)

	// SetTerminalModes sets the terminal modes from "pty-req"
	SetTerminalModes(ssh.TerminalModes)
}

// NewTerminal returns a new terminal. Terminal can be local or remote
// depending on cluster configuration.
func NewTerminal(ctx *ServerContext) (Terminal, error) {
	// doesn't matter what mode the cluster is in, if this is a teleport node
	// return a local terminal
	if ctx.srv.Component() == teleport.ComponentNode {
		return newLocalTerminal(ctx)
	}

	// otherwise find out what mode the cluster is in and return the
	// correct terminal
	clusterConfig, err := ctx.srv.GetAccessPoint().GetClusterConfig()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	if clusterConfig.GetSessionRecording() == services.RecordAtProxy {
		return newRemoteTerminal(ctx)
	}
	return newLocalTerminal(ctx)
}

// terminal is a local PTY created by Teleport nodes.
type terminal struct {
	wg sync.WaitGroup
	mu sync.Mutex

	log *log.Entry

	cmd *exec.Cmd
	ctx *ServerContext

	pty *os.File
	tty *os.File

	params rsession.TerminalParams
}

// NewLocalTerminal creates and returns a local PTY.
func newLocalTerminal(ctx *ServerContext) (*terminal, error) {
	pty, tty, err := pty.Open()
	if err != nil {
		log.Warnf("Could not start PTY %v", err)
		return nil, err
	}
	return &terminal{
		log: log.WithFields(log.Fields{
			trace.Component: teleport.ComponentLocalTerm,
		}),
		ctx: ctx,
		pty: pty,
		tty: tty,
	}, nil
}

// AddParty adds another participant to this terminal. We will keep the
// Terminal open until all participants have left.
func (t *terminal) AddParty(delta int) {
	t.wg.Add(delta)
}

// Run will run the terminal.
func (t *terminal) Run() error {
	defer t.closeTTY()

	cmd, err := prepareInteractiveCommand(t.ctx)
	if err != nil {
		return trace.Wrap(err)
	}
	t.cmd = cmd

	cmd.Stdout = t.tty
	cmd.Stdin = t.tty
	cmd.Stderr = t.tty
	cmd.SysProcAttr.Setctty = true
	cmd.SysProcAttr.Setsid = true

	err = cmd.Start()
	if err != nil {
		return trace.Wrap(err)
	}

	return nil
}

// Wait will block until the terminal is complete.
func (t *terminal) Wait() (*ExecResult, error) {
	err := t.cmd.Wait()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			status := exitErr.Sys().(syscall.WaitStatus)
			return &ExecResult{Code: status.ExitStatus(), Command: t.cmd.Path}, nil
		}
		return nil, err
	}

	status, ok := t.cmd.ProcessState.Sys().(syscall.WaitStatus)
	if !ok {
		return nil, trace.Errorf("unknown exit status: %T(%v)", t.cmd.ProcessState.Sys(), t.cmd.ProcessState.Sys())
	}

	return &ExecResult{
		Code:    status.ExitStatus(),
		Command: t.cmd.Path,
	}, nil
}

// Kill will force kill the terminal.
func (t *terminal) Kill() error {
	if t.cmd.Process != nil {
		if err := t.cmd.Process.Kill(); err != nil {
			if err.Error() != "os: process already finished" {
				return trace.Wrap(err)
			}
		}
	}

	return nil
}

// PTY returns the PTY backing the terminal.
func (t *terminal) PTY() io.ReadWriter {
	return t.pty
}

// TTY returns the TTY backing the terminal.
func (t *terminal) TTY() *os.File {
	return t.tty
}

// Close will free resources associated with the terminal.
func (t *terminal) Close() error {
	var err error
	// note, pty is closed in the copying goroutine,
	// not here to avoid data races
	if t.tty != nil {
		if e := t.tty.Close(); e != nil {
			err = e
		}
	}
	go t.closePTY()
	return trace.Wrap(err)
}

func (t *terminal) closeTTY() {
	if err := t.tty.Close(); err != nil {
		t.log.Warnf("Failed to close TTY: %v", err)
	}
	t.tty = nil
}

func (t *terminal) closePTY() {
	t.mu.Lock()
	defer t.mu.Unlock()
	defer t.log.Debugf("Closed PTY")

	// wait until all copying is over (all participants have left)
	t.wg.Wait()

	t.pty.Close()
	t.pty = nil
}

// GetWinSize returns the window size of the terminal.
func (t *terminal) GetWinSize() (*term.Winsize, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.pty == nil {
		return nil, trace.NotFound("no pty")
	}
	ws, err := term.GetWinsize(t.pty.Fd())
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return ws, nil
}

// SetWinSize sets the window size of the terminal.
func (t *terminal) SetWinSize(params rsession.TerminalParams) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.pty == nil {
		return trace.NotFound("no pty")
	}
	if err := term.SetWinsize(t.pty.Fd(), params.Winsize()); err != nil {
		return trace.Wrap(err)
	}
	t.params = params
	return nil
}

// GetTerminalParams is a fast call to get cached terminal parameters
// and avoid extra system call.
func (t *terminal) GetTerminalParams() rsession.TerminalParams {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.params
}

// SetTermType sets the terminal type from "req-pty" request.
func (t *terminal) SetTermType(term string) {
	if t.cmd != nil {
		t.cmd.Env = append(t.cmd.Env, "TERM="+term)
	}
}

func (t *terminal) SetTerminalModes(termModes ssh.TerminalModes) {
	return
}

type remoteTerminal struct {
	wg sync.WaitGroup
	mu sync.Mutex

	log *log.Entry

	ctx *ServerContext

	session   *ssh.Session
	params    rsession.TerminalParams
	termModes ssh.TerminalModes
	ptyBuffer *ptyBuffer
	termType  string
}

func newRemoteTerminal(ctx *ServerContext) (*remoteTerminal, error) {
	if ctx.RemoteSession == nil {
		return nil, trace.BadParameter("remote session required")
	}

	t := &remoteTerminal{
		log: log.WithFields(log.Fields{
			trace.Component: teleport.ComponentRemoteTerm,
		}),
		ctx:       ctx,
		session:   ctx.RemoteSession,
		ptyBuffer: &ptyBuffer{},
	}

	return t, nil
}

func (t *remoteTerminal) AddParty(delta int) {
	t.wg.Add(delta)
}

type ptyBuffer struct {
	r io.Reader
	w io.Writer
}

func (b *ptyBuffer) Read(p []byte) (n int, err error) {
	return b.r.Read(p)
}

func (b *ptyBuffer) Write(p []byte) (n int, err error) {
	return b.w.Write(p)
}

func (t *remoteTerminal) Run() error {
	// prepare the remote remote session by setting environment variables
	t.prepareRemoteSession(t.session, t.ctx)

	// combine stdout and stderr
	stdout, err := t.session.StdoutPipe()
	if err != nil {
		return trace.Wrap(err)
	}
	t.session.Stderr = t.session.Stdout
	stdin, err := t.session.StdinPipe()
	if err != nil {
		return trace.Wrap(err)
	}

	// create a pty buffer that stdin and stdout are hooked up to
	t.ptyBuffer = &ptyBuffer{
		r: stdout,
		w: stdin,
	}

	// if a specific term type was not requested, then pick the default one and request a pty
	if t.termType == "" {
		t.termType = defaultTerm
	}

	if err := t.session.RequestPty(t.termType, t.params.W, t.params.H, t.termModes); err != nil {
		return trace.Wrap(err)
	}

	// we want to run a "exec" command within a pty
	if t.ctx.ExecRequest.GetCommand() != "" {
		t.log.Debugf("Running exec request within a PTY")

		if err := t.session.Start(t.ctx.ExecRequest.GetCommand()); err != nil {
			return trace.Wrap(err)
		}

		return nil
	}

	// we want an interactive shell
	t.log.Debugf("Requesting an interactive terminal of type %v", t.termType)
	if err := t.session.Shell(); err != nil {
		return trace.Wrap(err)
	}
	return nil
}

func (t *remoteTerminal) Wait() (*ExecResult, error) {
	err := t.session.Wait()
	if err != nil {
		if exitErr, ok := err.(*ssh.ExitError); ok {
			return &ExecResult{
				Code:    exitErr.ExitStatus(),
				Command: t.ctx.ExecRequest.GetCommand(),
			}, err
		}

		return &ExecResult{
			Code:    teleport.RemoteCommandFailure,
			Command: t.ctx.ExecRequest.GetCommand(),
		}, err
	}

	return &ExecResult{
		Code:    teleport.RemoteCommandSuccess,
		Command: t.ctx.ExecRequest.GetCommand(),
	}, nil
}

func (t *remoteTerminal) Kill() error {
	err := t.session.Signal(ssh.SIGKILL)
	if err != nil {
		return trace.Wrap(err)
	}

	return nil
}

func (t *remoteTerminal) PTY() io.ReadWriter {
	return t.ptyBuffer
}

func (t *remoteTerminal) TTY() *os.File {
	return nil
}

func (t *remoteTerminal) Close() error {
	// this closes the underlying stdin,stdout,stderr which is what ptyBuffer is
	// hooked to directly
	err := t.session.Close()
	if err != nil {
		return trace.Wrap(err)
	}

	t.log.Debugf("Closed remote terminal and underlying SSH session")

	return nil
}

func (t *remoteTerminal) GetWinSize() (*term.Winsize, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	return t.params.Winsize(), nil
}

func (t *remoteTerminal) SetWinSize(params rsession.TerminalParams) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	err := t.windowChange(params.W, params.H)
	if err != nil {
		return trace.Wrap(err)
	}
	t.params = params

	return nil
}

func (t *remoteTerminal) GetTerminalParams() rsession.TerminalParams {
	t.mu.Lock()
	defer t.mu.Unlock()

	return t.params
}

func (t *remoteTerminal) SetTermType(term string) {
	t.termType = term
}

func (t *remoteTerminal) SetTerminalModes(termModes ssh.TerminalModes) {
	t.termModes = termModes
}

func (t *remoteTerminal) windowChange(w int, h int) error {
	type windowChangeRequest struct {
		W   uint32
		H   uint32
		Wpx uint32
		Hpx uint32
	}
	req := windowChangeRequest{
		W:   uint32(w),
		H:   uint32(h),
		Wpx: uint32(w * 8),
		Hpx: uint32(h * 8),
	}
	_, err := t.session.SendRequest(sshutils.WindowChangeRequest, false, ssh.Marshal(&req))
	return err
}

// prepareRemoteSession prepares the more session for execution.
func (t *remoteTerminal) prepareRemoteSession(session *ssh.Session, ctx *ServerContext) {
	envs := map[string]string{
		teleport.SSHTeleportUser:        ctx.Identity.TeleportUser,
		teleport.SSHSessionWebproxyAddr: ctx.ProxyPublicAddress(),
		teleport.SSHTeleportHostUUID:    ctx.srv.ID(),
		teleport.SSHTeleportClusterName: ctx.ClusterName,
		teleport.SSHSessionID:           string(ctx.session.id),
	}

	for k, v := range envs {
		if err := session.Setenv(k, v); err != nil {
			t.log.Debugf("Unable to set environment variable: %v: %v", k, v)
		}
	}
}
