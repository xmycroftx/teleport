package tlsca

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"time"

	"github.com/gravitational/teleport"

	"github.com/gravitational/trace"
	"github.com/jonboulle/clockwork"
	"github.com/sirupsen/logrus"
)

var log = logrus.WithFields(logrus.Fields{
	trace.Component: teleport.ComponentAuthority,
})

// New returns new CA from PEM encoded certificate and private
// key. Private Key is optional, if omitted CA won't be able to
// issue new certificates, only verify them
func New(certPEM, keyPEM []byte) (*CertAuthority, error) {
	ca := &CertAuthority{}
	var err error
	ca.Cert, err = ParseCertificatePEM(certPEM)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	if len(keyPEM) != 0 {
		ca.Signer, err = ParsePrivateKeyPEM(keyPEM)
		if err != nil {
			return nil, trace.Wrap(err)
		}
	}
	return ca, nil
}

type CertAuthority struct {
	// Cert is a CA certificate
	Cert *x509.Certificate
	// Signer is a private key based signer
	Signer crypto.Signer
}

type Identity struct {
	Username string
	Groups   []string
}

func (i *Identity) CheckAndSetDefaults() error {
	if i.Username == "" {
		return trace.BadParameter("missing identity username")
	}
	if len(i.Groups) == 0 {
		return trace.BadParameter("missing identity groups")
	}
	return nil
}

func (id *Identity) Subject() pkix.Name {
	subject := pkix.Name{
		CommonName: id.Username,
	}
	subject.Organization = append([]string{}, id.Groups...)
	return subject
}

func FromSubject(subject pkix.Name) (*Identity, error) {
	i := &Identity{
		Username: subject.CommonName,
		Groups:   subject.Organization,
	}
	if err := i.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}
	return i, nil
}

type CSRRequest struct {
	CSR      []byte
	NotAfter time.Time `json:"not_after"`
}

type CertificateRequest struct {
	Clock     clockwork.Clock
	PublicKey crypto.PublicKey
	Subject   pkix.Name
	NotAfter  time.Time
	DNSNames  []string
}

func (c *CertificateRequest) CheckAndSetDefaults() error {
	if c.Clock == nil {
		return trace.BadParameter("missing parameter Clock")
	}
	if c.PublicKey == nil {
		return trace.BadParameter("missing parameter PublicKey")
	}
	if c.Subject.CommonName == "" {
		return trace.BadParameter("missing parameter Subject.Common name")
	}
	if c.NotAfter.IsZero() {
		return trace.BadParameter("missing parameter NotAfter")
	}
	return nil
}

func (ca *CertAuthority) GenerateCertificate(req CertificateRequest) ([]byte, error) {
	if err := req.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	log.WithFields(logrus.Fields{
		"not_after":   req.NotAfter,
		"dns_names":   req.DNSNames,
		"common_name": req.Subject.CommonName,
		"org":         req.Subject.Organization,
	}).Infof("Generating TLS certificate.")

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      req.Subject,
		// substitue one minute to prevent "Not yet valid" errors on time scewed clusters
		NotBefore:             req.Clock.Now().UTC().Add(-1 * time.Minute),
		NotAfter:              req.NotAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true, // no intermediate certs allowed
		IsCA:     false,
		DNSNames: req.DNSNames,
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, ca.Cert, req.PublicKey, ca.Signer)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes}), nil
}

// ProcessCSR processes Certificate signing request and generates certificate back
// returns PEM encoded certificate in case if successfull
func (ca *CertAuthority) ProcessCSR(clock clockwork.Clock, req CSRRequest) ([]byte, error) {
	if ca.Signer == nil {
		return nil, trace.BadParameter("this CA has no signer, can not process CSR")
	}
	csr, err := ParseCertificateRequestPEM(req.CSR)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return ca.GenerateCertificate(CertificateRequest{
		Clock:     clock,
		PublicKey: csr.PublicKey,
		Subject:   csr.Subject,
		NotAfter:  req.NotAfter,
		DNSNames:  csr.DNSNames,
	})
}
