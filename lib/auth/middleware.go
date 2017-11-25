package auth

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"

	"github.com/gravitational/teleport/lib/limiter"
	"github.com/gravitational/teleport/lib/tlsca"

	"github.com/gravitational/teleport"
	"github.com/gravitational/trace"
	"github.com/sirupsen/logrus"
)

// TLSServerConfig is a configuration for TLS server
type TLSServerConfig struct {
	// TLS is a base TLS configuration
	TLS *tls.Config
	// API is API server configuration
	APIConfig
	// LimiterConfig is limiter config
	LimiterConfig limiter.LimiterConfig
}

func (c *TLSServerConfig) CheckAndSetDefaults() error {
	if c.TLS == nil {
		return trace.BadParameter("missing parameter TLS")
	}
	c.TLS.ClientAuth = tls.VerifyClientCertIfGiven
	if c.TLS.ClientCAs == nil {
		return trace.BadParameter("missing parameter TLS.ClientCAs")
	}
	if c.TLS.RootCAs == nil {
		return trace.BadParameter("missing parameter TLS.RootCAs")
	}
	if len(c.TLS.Certificates) == 0 {
		return trace.BadParameter("missing parameter TLS.Certificates")
	}
	if c.AuthServer == nil {
		return trace.BadParameter("missing parameter AuthServer")
	}
	return nil
}

type TLSServer struct {
	*http.Server
	TLSServerConfig
}

func NewTLSServer(cfg TLSServerConfig) (*TLSServer, error) {
	if err := cfg.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}
	// limiter limits requests by frequency and amount of simultaneous
	// connections per client
	limiter, err := limiter.NewLimiter(cfg.LimiterConfig)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	// authMiddleware authenticates request assuming TLS client authentication
	// adds authentication infromation to the context
	// and passes it to the API server
	authMiddleware := &AuthMiddleware{AuthServer: cfg.AuthServer}
	authMiddleware.Wrap(NewAPIServer(&cfg.APIConfig))
	// Wrap sets the next middleware in chain to the authMiddleware
	limiter.WrapHandle(authMiddleware)
	server := &TLSServer{
		TLSServerConfig: cfg,
		Server: &http.Server{
			Handler: limiter,
		},
	}
	server.TLS.GetConfigForClient = server.GetConfigForClient
	return server, nil
}

// Serve takes TCP listener, upgrades to TLS using config and starts serving
func (t *TLSServer) Serve(listener net.Listener) error {
	return t.Server.Serve(tls.NewListener(listener, t.TLS))
}

// GetConfigForClient is getting called on every connection
// and server's GetConfigForClient reloads the list of trusted
// local and remote certificate authorities
func (t *TLSServer) GetConfigForClient(info *tls.ClientHelloInfo) (*tls.Config, error) {
	// update client certificate pool based on currently trusted TLS
	// certificate authorities.
	// TODO(klizhentas) drop connectoins of the TLS cert authorities
	// that are not trusted
	// TODO(klizhentas) what are performance implications of returning new config
	// per connections? E.g. what happens to session tickets. Benchmark this
	pool, err := t.AuthServer.ClientCertPool()
	if err != nil {
		log.Errorf("failed to retrieve client pool: %v", trace.DebugReport(err))
		// this falls back to the default config
		return nil, nil
	}
	tlsCopy := t.TLS.Clone()
	tlsCopy.ClientCAs = pool
	return tlsCopy, nil
}

// AuthMiddleware is authentication middleware
type AuthMiddleware struct {
	AuthServer *AuthServer
	Handler    http.Handler
}

// Wrap sets next middleware in chain to the h
func (a *AuthMiddleware) Wrap(h http.Handler) {
	a.Handler = h
}

func (a *AuthMiddleware) GetUser(r *http.Request) (interface{}, error) {
	peers := r.TLS.PeerCertificates
	// with no client authentication in place, middleware
	// assumes not-privileged Nop role.
	// it theoretically possible to use bearer token auth even
	// for connections without auth, but this is not active use-case
	// therefore it is not allowed to reduce scope
	if len(peers) == 0 {
		log.WithFields(logrus.Fields{"type": "builtinb", "roles": teleport.RoleNop}).Debug("Authenticated user.")
		return BuiltinRole{
			GetClusterConfig: a.AuthServer.getCachedClusterConfig,
			Role:             teleport.RoleNop,
		}, nil
	}
	clientCert := peers[0]
	if len(clientCert.Issuer.Organization) < 1 {
		log.Warning("missing organization in issuer certificate %v", clientCert.Issuer)
		return nil, trace.AccessDenied("access denied: invalid client certificate")
	}
	certClusterName := clientCert.Issuer.Organization[0]
	localClusterName, err := a.AuthServer.GetDomainName()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	identity, err := tlsca.FromSubject(clientCert.Subject)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	// TODO(klizhentas) add audit events here during login

	// this block assumes interactive user from remote cluster
	// based on the remote certificate authority cluster name encoded in
	// x509 organization name
	if certClusterName != localClusterName {
		// make sure that this user does not have system role
		// the local auth server can not truste remote servers
		// to issue certificates with system roles (e.g. Admin),
		// to get unrestricted access to the local cluster
		systemRole := findSystemRole(identity.Groups)
		if systemRole != nil {
			log.Warningf("Trusted Cluster %q attempted to get access with system role %v!", certClusterName, *systemRole)
			return nil, trace.AccessDenied("unsupported role %q for remote user", *systemRole)
		}
		log.WithFields(logrus.Fields{"user": identity.Username, "type": "remote", "roles": identity.Groups, "cluster": certClusterName}).Debug("Authenticated user.")
		return RemoteUser{
			ClusterName: certClusterName,
			Username:    identity.Username,
			RemoteRoles: identity.Groups,
		}, nil
	}
	// code below expects user or service from local cluster, to distinguish between
	// interactive users and services (e.g. proxies), the code below
	// checks for presense of system roles issued in certificate identity
	systemRole := findSystemRole(identity.Groups)
	// in case if the system role is present, assume this is a service
	// agent, e.g. Proxy, connecting to the cluster
	if systemRole != nil {
		log.WithFields(logrus.Fields{"type": "builtin", "roles": identity.Groups, "cluster": certClusterName}).Debug("Authenticated user.")
		return BuiltinRole{
			GetClusterConfig: a.AuthServer.getCachedClusterConfig,
			Role:             *systemRole,
		}, nil
	}
	log.WithFields(logrus.Fields{"user": identity.Username, "type": "local", "cluster": certClusterName}).Debug("Authenticated user.")
	// otherwise assume that is a local role, no need to pass the roles
	// as it will be fetched from the local database
	return LocalUser{
		Username: identity.Username,
	}, nil
}

func findSystemRole(roles []string) *teleport.Role {
	for _, role := range roles {
		systemRole := teleport.Role(role)
		err := systemRole.Check()
		if err == nil {
			return &systemRole
		}
	}
	return nil
}

func (a *AuthMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	baseContext := r.Context()
	if baseContext == nil {
		baseContext = context.TODO()
	}
	user, err := a.GetUser(r)
	if err != nil {
		trace.WriteError(w, err)
		return
	}

	// determine authenticated user based on the request parameters
	requestWithContext := r.WithContext(context.WithValue(baseContext, ContextUser, user))
	a.Handler.ServeHTTP(w, requestWithContext)
}
