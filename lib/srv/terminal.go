/*
Copyright 2017 Gravitational, Inc.

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

	"github.com/gravitational/teleport/lib/session"

	"github.com/gravitational/trace"

	"github.com/kr/pty"
	"github.com/moby/moby/pkg/term"
	log "github.com/sirupsen/logrus"
)

// Terminal defines an interface of functions for managing a (local or remote)
// PTY such as: executing commands within a PTY, resizing windows, and
// cleaning up.
type Terminal interface {
	// AddParty adds another participant to this terminal. We will keep the
	// Terminal open until all participants have left.
	AddParty(delta int)

	Run() error
	Wait() (*ExecResult, error)
	Kill() error

	PTY() io.ReadWriter
	TTY() *os.File

	Close() error

	GetWinSize() (*term.Winsize, error)
	SetWinSize(params session.TerminalParams) error
	GetTerminalParams() session.TerminalParams
	SetTermType(string)
}

// NewTerminal returns either a regular.terminal or forward.terminal depending
// on the mode the proxy is running in.
func NewTerminal(ctx *SessionContext) (Terminal, error) {
	return NewLocalTerminal(ctx)
}

// localTerminal is a local PTY created by Teleport nodes.
type localTerminal struct {
	wg sync.WaitGroup
	mu sync.Mutex

	cmd *exec.Cmd
	ctx *SessionContext

	pty *os.File
	tty *os.File

	params session.TerminalParams
}

// NewLocalTerminal creates and returns a local PTY.
func NewLocalTerminal(ctx *SessionContext) (*localTerminal, error) {
	pty, tty, err := pty.Open()
	if err != nil {
		log.Warnf("could not start pty (%s)", err)
		return nil, err
	}

	return &localTerminal{
		ctx: ctx,
		pty: pty,
		tty: tty,
	}, nil
}

func (t *localTerminal) AddParty(delta int) {
	t.wg.Add(delta)
}

func (t *localTerminal) Run() error {
	defer t.closeTTY()

	cmd, err := prepInteractiveCommand(t.ctx)
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

func (t *localTerminal) Wait() (*ExecResult, error) {
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

func (t *localTerminal) Kill() error {
	if t.cmd.Process != nil {
		if err := t.cmd.Process.Kill(); err != nil {
			if err.Error() != "os: process already finished" {
				return trace.Wrap(err)
			}
		}
	}

	return nil
}

func (t *localTerminal) PTY() io.ReadWriter {
	return t.pty
}

func (t *localTerminal) TTY() *os.File {
	return t.tty
}

func (t *localTerminal) SetTermType(term string) {
	if term == "" {
		term = defaultTerm
	}
	// TODO(russjones): See if we have defined term already.
	t.cmd.Env = append(t.cmd.Env, "TERM="+term)
}

func (t *localTerminal) GetWinSize() (*term.Winsize, error) {
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

func (t *localTerminal) SetWinSize(params session.TerminalParams) error {
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

// getTerminalParams is a fast call to get cached localTerminal parameters
// and avoid extra system call
func (t *localTerminal) GetTerminalParams() session.TerminalParams {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.params
}

func (t *localTerminal) closeTTY() {
	if err := t.tty.Close(); err != nil {
		log.Warnf("failed to close TTY: %v", err)
	}
	t.tty = nil
}

func (t *localTerminal) Close() error {
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

func (t *localTerminal) closePTY() {
	t.mu.Lock()
	defer t.mu.Unlock()
	defer log.Debugf("PTY is closed")

	// wait until all copying is over (all participants have left)
	t.wg.Wait()

	t.pty.Close()
	t.pty = nil
}
