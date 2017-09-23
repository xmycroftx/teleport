package srv

import (
	"crypto/subtle"
	"net"

	"golang.org/x/crypto/ssh"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/trace"
)

func remoteSession(ctx *ServerContext) (*ssh.Session, error) {
	hostKeyChecker := func(hostport string, remote net.Addr, key ssh.PublicKey) error {
		ca, err := getHostCA(ctx.srv.GetAuthService(), ctx.ClusterName)
		if err != nil {
			return trace.Wrap(err)
		}

		checkers, err := ca.Checkers()
		if err != nil {
			return trace.Wrap(err)
		}

		for _, checker := range checkers {
			caMatch := subtle.ConstantTimeCompare(checker.Marshal(), key.Marshal()) == 1
			if caMatch {
				return trace.Wrap(err)
			}
		}
		return nil
	}

	//checker := &ssh.CertChecker{
	//	IsAuthority: func(p ssh.PublicKey) bool {
	//		ca, err := getHostCA(ctx.srv.GetAuthService(), ctx.ClusterName)
	//		if err != nil {
	//			return false
	//		}

	//		checkers, err := ca.Checkers()
	//		if err != nil {
	//			return false
	//		}

	//		for _, checker := range checkers {
	//			caMatch := subtle.ConstantTimeCompare(checker.Marshal(), p.Marshal()) == 1
	//			if caMatch {
	//				return false
	//			}
	//		}
	//		return false
	//	},
	//}

	// TODO(russjones): Wait for the agent to be ready or a timeout.
	<-ctx.AgentReady
	authMethod := ssh.PublicKeysCallback(ctx.agent.Signers)

	clientConfig := &ssh.ClientConfig{
		User: ctx.Login,
		Auth: []ssh.AuthMethod{
			authMethod,
		},
		HostKeyCallback: hostKeyChecker,
		Timeout:         defaults.DefaultDialTimeout,
	}

	client, err := ssh.Dial("tcp", ctx.srv.AdvertiseAddr(), clientConfig)
	if err != nil {
		return nil, err
	}

	session, err := client.NewSession()
	if err != nil {
		return nil, err
	}

	return session, nil
}

func collectRemoteStatus(err error) (*ExecResult, error) {
	if err != nil {
		if exitErr, ok := err.(*ssh.ExitError); ok {
			return &ExecResult{
				Code:    exitErr.ExitStatus(),
				Command: "forward-shell",
			}, err
		}

		return &ExecResult{
			Code:    teleport.RemoteCommandFailure,
			Command: "forward-shell",
		}, err
	}

	return &ExecResult{
		Code:    teleport.RemoteCommandSuccess,
		Command: "forward-shell",
	}, nil
}
