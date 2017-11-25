package auth

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/utils"

	"github.com/gravitational/trace"
	"github.com/pborman/uuid"
	"github.com/tstranex/u2f"
)

type AuthenticateUserRequest struct {
	Username string                `json:"username"`
	Pass     *PassCreds            `json:"pass,omitempty"`
	U2F      *U2FSignResponseCreds `json:"u2f,omitempty"`
	OTP      *OTPCreds             `json:"otp,omitempty"`
	Session  *SessionCreds         `json:"session,omitempty"`
}

func (a *AuthenticateUserRequest) CheckAndSetDefaults() error {
	if a.Username == "" {
		return trace.BadParameter("missing parameter 'username'")
	}
	if a.Pass == nil && a.U2F == nil && a.OTP == nil {
		return trace.BadParameter("at least one authentication method is required")
	}
	return nil
}

type PassCreds struct {
	Password []byte `json:"password"`
}

type U2FSignResponseCreds struct {
	SignResponse u2f.SignResponse `json:"sign_response"`
}

type OTPCreds struct {
	Password []byte `json:"password"`
	Token    string `json:"token"`
}

type SessionCreds struct {
	ID string `json:"id"`
}

// AuthenticateUser authenticates user based on the request type
func (s *AuthServer) AuthenticateUser(req AuthenticateUserRequest) error {
	if err := req.CheckAndSetDefaults(); err != nil {
		return trace.Wrap(err)
	}

	authPreference, err := s.GetAuthPreference()
	if err != nil {
		return trace.Wrap(err)
	}

	switch {
	case req.Pass != nil:
		// authenticate using password only, make sure
		// that auth preference does not require second factor
		// otherwise users can bypass the second factor
		if authPreference.GetSecondFactor() != teleport.OFF {
			return trace.AccessDenied("missing second factor")
		}
		err := s.WithUserLock(req.Username, func() error {
			return s.CheckPasswordWOToken(req.Username, req.Pass.Password)
		})
		return trace.Wrap(err)
	case req.U2F != nil:
		// authenticate using U2F - code checks challenge response
		// signed by U2F device of the user
		err := s.WithUserLock(req.Username, func() error {
			return s.CheckU2FSignResponse(req.Username, &req.U2F.SignResponse)
		})
		return trace.Wrap(err)
	case req.OTP != nil:
		err := s.WithUserLock(req.Username, func() error {
			return s.CheckPassword(req.Username, req.OTP.Password, req.OTP.Token)
		})
		return trace.Wrap(err)
	default:
		return trace.AccessDenied("unsupported authentication method")
	}
}

// AuthenticateWebUser authenticates web user, creates and  returns web session
// in case if authentication is successfull. In case if existing session id
// is used to authenticate, returns session associated with the existing session id
// instead of creating the new one
func (s *AuthServer) AuthenticateWebUser(req AuthenticateUserRequest) (services.WebSession, error) {
	if req.Session != nil {
		session, err := s.GetWebSession(req.Username, req.Session.ID)
		if err != nil {
			return nil, trace.AccessDenied("session is invalid or has expired")
		}
		return session, nil
	}
	if err := s.AuthenticateUser(req); err != nil {
		return nil, trace.Wrap(err)
	}
	sess, err := s.NewWebSession(req.Username)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	if err := s.UpsertWebSession(req.Username, sess); err != nil {
		return nil, trace.Wrap(err)
	}
	sess, err = services.GetWebSessionMarshaler().GenerateWebSession(sess)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return sess, nil
}

type AuthenticateSSHRequest struct {
	AuthenticateUserRequest
	// PublicKey is public key in ssh authorized_keys format
	PublicKey         []byte        `json:"public_key"`
	TTL               time.Duration `json:"ttl"`
	CompatibilityMode string        `json:"compatibility_mode"`
}

func (a *AuthenticateSSHRequest) CheckAndSetDefaults() error {
	if err := a.AuthenticateUserRequest.CheckAndSetDefaults(); err != nil {
		return trace.Wrap(err)
	}
	if len(a.PublicKey) == 0 {
		return trace.BadParameter("missing parameter 'public_key'")
	}
	compatibility, err := utils.CheckCompatibilityFlag(a.CompatibilityMode)
	if err != nil {
		return trace.Wrap(err)
	}
	a.CompatibilityMode = compatibility
	return nil
}

// SSHLoginResponse is a response returned by web proxy, it preserves backwards compatibility
// on the wire, which is the primary reason for non-matching json tags
type SSHLoginResponse struct {
	// User contains a logged in user informationn
	Username string `json:"username"`
	// Cert is PEM encoded  signed certificate
	Cert []byte `json:"cert"`
	// TLSCertPEM is a PEM encoded TLS certificate signed by TLS certificate authority
	TLSCert []byte `json:"tls_cert"`
	// HostSigners is a list of signing host public keys trusted by proxy
	HostSigners []TrustedCerts `json:"host_signers"`
}

// TrustedCerts contains host certificates, it preserves backwards compatibility
// on the wire, which is the primary reason for non-matching json tags
type TrustedCerts struct {
	// ClusterName identifies teleport cluster name this authority serves,
	// for host authorities that means base hostname of all servers,
	// for user authorities that means organization name
	ClusterName string `json:"domain_name"`
	// HostCertificates is a list of SSH public keys that can be used to check
	// host certificate signatures
	HostCertificates [][]byte `json:"checking_keys"`
	// TLSCertificates  is a list of TLS certificates of the certificate authoritiy
	// of the authentication server
	TLSCertificates [][]byte `json:"tls_certs"`
}

// SSHCertPublicKeys returns a list of trusted host SSH certificate authority public keys
func (c *TrustedCerts) SSHCertPublicKeys() ([]ssh.PublicKey, error) {
	out := make([]ssh.PublicKey, 0, len(c.HostCertificates))
	for _, keyBytes := range c.HostCertificates {
		publicKey, _, _, _, err := ssh.ParseAuthorizedKey(keyBytes)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		out = append(out, publicKey)
	}
	return out, nil
}

// AuthoritiesToTrustedCerts serializes authorities to TrustedCerts data structure
func AuthoritiesToTrustedCerts(authorities []services.CertAuthority) []TrustedCerts {
	out := make([]TrustedCerts, len(authorities))
	for i, ca := range authorities {
		out[i] = TrustedCerts{
			ClusterName:      ca.GetClusterName(),
			HostCertificates: ca.GetCheckingKeys(),
			TLSCertificates:  services.TLSCerts(ca),
		}
	}
	return out
}

// AuthenticateSSHUser authenticates web user, creates and  returns web session
// in case if authentication is successfull
func (s *AuthServer) AuthenticateSSHUser(req AuthenticateSSHRequest) (*SSHLoginResponse, error) {
	if err := s.AuthenticateUser(req.AuthenticateUserRequest); err != nil {
		return nil, trace.Wrap(err)
	}
	user, err := s.GetUser(req.Username)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	roles, err := services.FetchRoles(user.GetRoles(), s, user.GetTraits())
	if err != nil {
		return nil, trace.Wrap(err)
	}
	hostCertAuthorities, err := s.GetCertAuthorities(services.HostCA, false)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	certs, err := s.generateUserCert(certRequest{
		user:          user,
		roles:         roles,
		ttl:           req.TTL,
		publicKey:     req.PublicKey,
		compatibility: req.CompatibilityMode,
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return &SSHLoginResponse{
		Username:    req.Username,
		Cert:        certs.ssh,
		TLSCert:     certs.tls,
		HostSigners: AuthoritiesToTrustedCerts(hostCertAuthorities),
	}, nil
}

// CreateCertExchange initiates certificate exchange operation, if successfull,
// returns a token encrypted by certificate authority public key
// in SSH authorized_keys format
func (s *AuthServer) CreateCertExchange(publicKeyBytes []byte) (string, error) {
	ca, err := s.findCertAuthorityByPublicKey(publicKeyBytes)
	if err != nil {
		return "", trace.AccessDenied("unrecognized public key")
	}

	token := uuid.New()
	encryptedToken, err := EncryptWithSSHPublicKey(ca.GetCheckingKeys()[0], []byte(token), []byte("kex"))
	if err != nil {
		log.Warningf("failed to create key exchange: %v", trace.DebugReport(err))
		return "", trace.AccessDenied("internal error kex[01]")
	}

	certExchangeToken := services.CertExchangeToken{
		Metadata: services.Metadata{
			Name: token,
		},
		ClusterName: ca.GetName(),
	}
	certExchangeToken.Metadata.SetExpiry(s.clock.Now().Add(defaults.InviteTokenTTL))

	err = s.Identity.CreateCertExchangeToken(certExchangeToken)
	if err != nil {
		log.Warningf("failed to create cert exchange: %v", trace.DebugReport(err))
		return "", trace.AccessDenied("internal error kex[02]")
	}

	return *encryptedToken, nil
}

type CertExchangeRequest struct {
	Token   string `json:"token"`
	TLSCert []byte `json:"tls_cert"`
}

func (req *CertExchangeRequest) CheckAndSetDefaults() error {
	if req.Token == "" {
		return trace.BadParameter("missing parameter 'token'")
	}
	if len(req.TLSCert) == 0 {
		return trace.BadParameter("missing parameter 'tls_cert'")
	}
	return nil
}

type CertExchangeResponse struct {
	TLSCert []byte `json:"tls_cert"`
}

func (s *AuthServer) CompleteCertExchange(req CertExchangeRequest) (*CertExchangeResponse, error) {
	if err := req.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}
	token, err := s.Identity.GetCertExchangeToken(req.Token)
	if err != nil {
		log.Warningf("failed to get token: %v", err)
		return nil, trace.AccessDenied("access denied: bad authentication token")
	}

	// token is one time, even though the code below can fail,
	// client will have to create new exchange operation
	err = s.Identity.DeleteCertExchangeToken(req.Token)
	if err != nil {
		if !trace.IsNotFound(err) {
			log.Warningf("failed to get token: %v", err)
			return nil, trace.AccessDenied("access denied: bad authentication token")
		}
	}

	clusterName, err := s.GetClusterName()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	thisHostCA, err := s.GetCertAuthority(services.CertAuthID{Type: services.HostCA, DomainName: clusterName.GetClusterName()}, false)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	trustedClusterCA, err := s.GetCertAuthority(services.CertAuthID{Type: services.HostCA, DomainName: token.ClusterName}, false)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	trustedClusterCA.SetTLSKeyPairs([]services.TLSKeyPair{
		{
			Cert: req.TLSCert,
		},
	})

	err = s.UpsertCertAuthority(trustedClusterCA)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return &CertExchangeResponse{
		TLSCert: thisHostCA.GetTLSKeyPairs()[0].Cert,
	}, nil
}

func (s *AuthServer) findCertAuthorityByPublicKey(publicKey []byte) (services.CertAuthority, error) {
	authorities, err := s.GetCertAuthorities(services.HostCA, false)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	for _, ca := range authorities {
		for _, key := range ca.GetCheckingKeys() {
			if bytes.Equal(key, publicKey) {
				return ca, nil
			}
		}
	}
	return nil, trace.NotFound("certificate authority with public key is not found")
}

func EncryptWithSSHPublicKey(publicKeyBytes []byte, message []byte, label []byte) (*string, error) {
	publicKey, _, _, _, err := ssh.ParseAuthorizedKey(publicKeyBytes)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	cryptoPubKey, ok := publicKey.(ssh.CryptoPublicKey)
	if !ok {
		return nil, trace.BadParameter("unexpected key type: %T", publicKey)
	}
	rsaPublicKey, ok := cryptoPubKey.CryptoPublicKey().(rsa.PublicKey)
	if !ok {
		return nil, trace.BadParameter("unexpected key type: %T", publicKey)
	}

	// crypto/rand.Reader is a good source of entropy for randomizing the
	// encryption function.
	rng := rand.Reader

	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rng, &rsaPublicKey, message, label)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	encoded := base64.StdEncoding.EncodeToString(ciphertext)
	return &encoded, nil
}

func DecryptWithSSHPrivateKey(ciphertext string, privateKeyBytes []byte, label []byte) (*string, error) {
	cipherBytes, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	privateKey, err := ssh.ParseRawPrivateKey(privateKeyBytes)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	rsaPrivateKey, ok := privateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, trace.BadParameter("expected RSA private key, got %v", privateKey)
	}

	// crypto/rand.Reader is a good source of entropy for blinding the RSA
	// operation.
	rng := rand.Reader

	plainBytes, err := rsa.DecryptOAEP(sha256.New(), rng, rsaPrivateKey, cipherBytes, label)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	plainText := string(plainBytes)

	return &plainText, nil
}
