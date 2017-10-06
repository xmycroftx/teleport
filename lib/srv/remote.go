package srv

import (
	//"crypto/subtle"
	"net"
	"os"
	//"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/sshutils"
	"github.com/gravitational/trace"
	//log "github.com/sirupsen/logrus"
)

var _ = os.SEEK_CUR
var _ = agent.ForwardToRemote

func RemoteSession(addr string, systemLogin string, userAuthAgent agent.Agent, authService auth.ClientI) (*ssh.Client, *ssh.Session, error) {
	hostKeyChecker := func(hostport string, remote net.Addr, key ssh.PublicKey) error {
		cert, ok := key.(*ssh.Certificate)
		if ok {
			// find cert authority by it's key
			cas, err := authService.GetCertAuthorities(services.HostCA, false)
			if err != nil {
				return trace.Wrap(err)
			}

			for i := range cas {
				checkers, err := cas[i].Checkers()
				if err != nil {
					return trace.Wrap(err)
				}

				for _, checker := range checkers {
					if sshutils.KeysEqual(cert.SignatureKey, checker) {
						return nil
					}
				}
			}

			return trace.BadParameter("invalid host cert")
			//ca, err := getHostCA(ctx.srv.GetAuthService(), ctx.ClusterName)
			//if err != nil {
			//	return trace.Wrap(err)
			//}

			//checkers, err := ca.Checkers()
			//if err != nil {
			//	return trace.Wrap(err)
			//}

			//for _, checker := range checkers {
			//	caMatch := subtle.ConstantTimeCompare(checker.Marshal(), key.Marshal()) == 1
			//	if caMatch {
			//		return nil
			//	}
			//}
			//return trace.BadParameter("invalid cert")
		}
		// take any valid public key and if we have gotten to this point we have a valid public key
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

	if userAuthAgent == nil {
		return nil, nil, trace.AccessDenied("no agent found in ProxyCommand")
	}
	authMethod := ssh.PublicKeysCallback(userAuthAgent.Signers)

	clientConfig := &ssh.ClientConfig{
		User: systemLogin,
		Auth: []ssh.AuthMethod{
			authMethod,
		},
		HostKeyCallback: hostKeyChecker,
		Timeout:         defaults.DefaultDialTimeout,
	}

	client, err := ssh.Dial("tcp", addr, clientConfig)
	if err != nil {
		return nil, nil, trace.Wrap(err)
	}

	session, err := client.NewSession()
	if err != nil {
		return nil, nil, trace.Wrap(err)
	}

	//err = prepareSession(session, ctx)
	//if err != nil {
	//	log.Warnf("[Remote Session] Unable to set environment variables on target host: %v", err)
	//}

	return client, session, nil
}

func CollectRemoteStatus(err error) (*ExecResult, error) {
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

func prepareSession(session *ssh.Session, ctx *ServerContext) error {
	if err := session.Setenv(teleport.SSHTeleportUser, ctx.TeleportUser); err != nil {
		return trace.BadParameter("unable to set environment variable: %v: %v", teleport.SSHTeleportUser, err)
	}
	//if err := session.Setenv(teleport.SSHSessionWebproxyAddr, proxyHost); err != nil {
	//	return trace.Wrap(err)
	//}
	if err := session.Setenv(teleport.SSHTeleportHostUUID, ctx.srv.ID()); err != nil {
		return trace.BadParameter("unable to set environment variable: %v: %v", teleport.SSHTeleportHostUUID, err)
	}
	if err := session.Setenv(teleport.SSHTeleportClusterName, ctx.ClusterName); err != nil {
		return trace.BadParameter("unable to set environment variable: %v: %v", teleport.SSHTeleportClusterName, err)
	}
	// TODO(russjones): fix this, it will panic when trying to connect to a node in a trusted cluster
	//if err := session.Setenv(teleport.SSHSessionID, string(ctx.session.id)); err != nil {
	//	return trace.BadParameter("unable to set environment variable: %v: %v", teleport.SSHSessionID, err)
	//}

	return nil
}
