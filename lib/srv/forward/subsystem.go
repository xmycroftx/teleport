package forward

import (
	"context"
	"io"

	"golang.org/x/crypto/ssh"

	"github.com/gravitational/teleport/lib/srv"
	"github.com/gravitational/trace"
)

type remoteSubsystem struct {
	ctx          *srv.ServerContext
	subsytemName string
	doneCtx      context.Context
}

func (r *remoteSubsystem) Start(ch ssh.Channel) error {
	//session, err := srv.RemoteSession(r.ctx)
	//if err != nil {
	//	return trace.Wrap(err)
	//}
	//r.session = session
	session := r.ctx.RemoteSession

	// combine stdout and stderr
	stdout, err := session.StdoutPipe()
	if err != nil {
		return trace.Wrap(err)
	}
	stderr, err := session.StderrPipe()
	if err != nil {
		return trace.Wrap(err)
	}
	stdin, err := session.StdinPipe()
	if err != nil {
		return trace.Wrap(err)
	}

	err = session.RequestSubsystem(r.subsytemName)
	if err != nil {
		return trace.Wrap(err)
	}
	r.ctx.Infof("[REMOTE SUBSYSTEM] Started subsystem: %q", r.subsytemName)

	doneCtx, cancel := context.WithCancel(context.Background())
	r.doneCtx = doneCtx

	go func() {
		io.Copy(ch, stdout)
		cancel()
	}()
	go func() {
		io.Copy(ch.Stderr(), stderr)
		cancel()
	}()
	go func() {
		io.Copy(stdin, ch)
		cancel()
	}()

	return nil
}

func (r *remoteSubsystem) Wait() error {
	// block until the remote subsystem has finished execution
	<-r.doneCtx.Done()
	r.ctx.Infof("[REMOTE SUBSYSTEM] Subsystem %q complete", r.subsytemName)

	// TODO(russjones): We should emit an event for subsystem requests.

	return nil
}
