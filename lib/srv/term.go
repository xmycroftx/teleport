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
	//"net"
	"os"
	"os/exec"
	"sync"
	"syscall"

	"golang.org/x/crypto/ssh"
	//"golang.org/x/crypto/ssh/agent"

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
	AddWaitCounter(delta int)

	Run(*ServerContext) error
	Wait() (*ExecResult, error)
	Kill() error

	PTY() io.ReadWriter
	TTY() *os.File

	Close() error

	GetWinSize() (*term.Winsize, error)
	SetWinSize(params rsession.TerminalParams) error
	GetTerminalParams() rsession.TerminalParams
}

// terminal is a local PTY created by Teleport nodes.
type terminal struct {
	wg sync.WaitGroup
	mu sync.Mutex

	cmd *exec.Cmd

	pty    *os.File
	tty    *os.File
	err    error
	done   bool
	params rsession.TerminalParams
}

// NewLocalTerminal creates and returns a local PTY.
func NewLocalTerminal() (*terminal, error) {
	pty, tty, err := pty.Open()
	if err != nil {
		log.Warnf("could not start pty (%s)", err)
		return nil, err
	}
	return &terminal{pty: pty, tty: tty, err: err}, nil
}

func (t *terminal) AddWaitCounter(delta int) {
	t.wg.Add(delta)
}

func (t *terminal) Run(ctx *ServerContext) error {
	defer t.closeTTY()

	cmd, err := prepInteractiveCommand(ctx)
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

func (t *terminal) Kill() error {
	if t.cmd.Process != nil {
		if err := t.cmd.Process.Kill(); err != nil {
			if err.Error() != "os: process already finished" {
				log.Error(trace.DebugReport(err))
			}
		}
	}

	return nil
}

func (t *terminal) PTY() io.ReadWriter {
	return t.pty
}

func (t *terminal) TTY() *os.File {
	return t.tty
}

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

// getTerminalParams is a fast call to get cached terminal parameters
// and avoid extra system call
func (t *terminal) GetTerminalParams() rsession.TerminalParams {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.params
}

func (t *terminal) closeTTY() {
	if err := t.tty.Close(); err != nil {
		log.Warnf("failed to close TTY: %v", err)
	}
	t.tty = nil
}

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

func (t *terminal) closePTY() {
	t.mu.Lock()
	defer t.mu.Unlock()
	defer log.Debugf("PTY is closed")

	// wait until all copying is over
	t.wg.Wait()

	t.pty.Close()
	t.pty = nil
}

func ParsePTYReq(req *ssh.Request) (*sshutils.PTYReqParams, error) {
	var r sshutils.PTYReqParams
	if err := ssh.Unmarshal(req.Payload, &r); err != nil {
		log.Warnf("failed to parse PTY request: %v", err)
		return nil, err
	}

	// if the caller asked for an invalid sized pty (like ansible
	// which asks for a 0x0 size) update the request with defaults
	if err := r.CheckAndSetDefaults(); err != nil {
		return nil, err
	}

	return &r, nil
}

//type remoteTerminal struct {
//	wg sync.WaitGroup
//	mu sync.Mutex
//
//	session     *ssh.Session
//	params      rsession.TerminalParams
//	sessionDone chan bool
//	ptyBuffer   *ptyBuffer
//}
//
//func NewRemoteTerminal(req *ssh.Request) (*remoteTerminal, *rsession.TerminalParams, error) {
//	r, err := parsePTYReq(req)
//	if err != nil {
//		return nil, nil, trace.Wrap(err)
//	}
//	log.Debugf("Parsed pty request pty(env=%v, w=%v, h=%v)", r.Env, r.W, r.H)
//
//	params, err := rsession.NewTerminalParamsFromUint32(r.W, r.H)
//	if err != nil {
//		return nil, nil, trace.Wrap(err)
//	}
//
//	// TODO(russjones): Get the agent from the user here.
//	systemAgent, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK"))
//	if err != nil {
//		return nil, nil, err
//	}
//	authMethod := ssh.PublicKeysCallback(agent.NewClient(systemAgent).Signers)
//
//	clientConfig := &ssh.ClientConfig{
//		User: "rjones",
//		Auth: []ssh.AuthMethod{
//			authMethod,
//		},
//		// TODO(russjones): Use a HostKeyCallback here to check the host key of the
//		// client we are connecting to.
//	}
//
//	// TODO(russjones): Add a timeout here. Add real remote host:port here.
//	// This should probably be passed into this function, so we don't always dial
//	// to the remote node.
//	client, err := ssh.Dial("tcp", "localhost:22", clientConfig)
//	if err != nil {
//		return nil, nil, err
//	}
//
//	session, err := client.NewSession()
//	if err != nil {
//		return nil, nil, err
//	}
//
//	t := &remoteTerminal{
//		session:     session,
//		sessionDone: make(chan bool),
//		ptyBuffer:   &ptyBuffer{},
//	}
//	t.SetWinSize(*params)
//
//	return t, params, nil
//}
//
//type ptyBuffer struct {
//	r io.Reader
//	w io.Writer
//}
//
//func (b *ptyBuffer) Read(p []byte) (n int, err error) {
//	return b.r.Read(p)
//}
//
//func (b *ptyBuffer) Write(p []byte) (n int, err error) {
//	return b.w.Write(p)
//}
//
//// TODO(russjones): We don't care what c actually is here.
//func (t *remoteTerminal) Run(c *exec.Cmd) error {
//	// combine stdout and stderr
//	stdout, err := t.session.StdoutPipe()
//	if err != nil {
//		return trace.Wrap(err)
//	}
//	t.session.Stderr = t.session.Stdout
//	stdin, err := t.session.StdinPipe()
//	if err != nil {
//		return trace.Wrap(err)
//	}
//
//	t.ptyBuffer = &ptyBuffer{
//		r: stdout,
//		w: stdin,
//	}
//
//	modes := ssh.TerminalModes{
//		ssh.ECHO:          1,
//		ssh.TTY_OP_ISPEED: 14400,
//		ssh.TTY_OP_OSPEED: 14400,
//	}
//
//	if err := t.session.RequestPty("xterm", 80, 40, modes); err != nil {
//		return err
//	}
//
//	if err := t.session.Shell(); err != nil {
//		return err
//	}
//
//	return nil
//}
//
//func (t *remoteTerminal) Wait() error {
//	<-t.sessionDone
//
//	// TODO(russjones): Who closes the channel here?
//
//	return nil
//}
//
//func (t *remoteTerminal) ReadWriter() io.ReadWriter {
//	return t.ptyBuffer
//}
//
//func (t *remoteTerminal) Close() error {
//	err := t.session.Close()
//	if err != nil {
//		return trace.Wrap(err)
//	}
//
//	return nil
//}
//
//func (t *remoteTerminal) GetWinSize() (*term.Winsize, error) {
//	return t.params.Winsize(), nil
//}
//
//func (t *remoteTerminal) SetWinSize(params rsession.TerminalParams) error {
//	// TODO(russjones): Revendor the SSH library so so we can update the window
//	// size here.
//	//err = session.WindowChange(params.H, params.W)
//	//if err != nil {
//	//    return nil, nil, err
//	//}
//	t.params = params
//	return nil
//}
//
//func (t *remoteTerminal) GetTerminalParams() rsession.TerminalParams {
//	return t.params
//}
