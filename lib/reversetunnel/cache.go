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

package reversetunnel

import (
	"net"
	"sync"

	"golang.org/x/crypto/ssh"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/auth/native"

	"github.com/gravitational/trace"
)

type hostCertificateCache struct {
	mu sync.Mutex

	authService auth.ClientI
	cache       map[string]ssh.Signer
}

func NewHostCertificateCache(authService auth.ClientI) *hostCertificateCache {
	return &hostCertificateCache{
		authService: authService,
		cache:       make(map[string]ssh.Signer),
	}
}

func (h *hostCertificateCache) get(addr string) (ssh.Signer, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	var certificate ssh.Signer
	var err error
	var ok bool

	// extract the principal from the address
	principal, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	certificate, ok = h.cache[principal]
	if !ok {
		certificate, err = h.generateHostCert(principal)
		if err != nil {
			return nil, trace.Wrap(err)
		}

		h.cache[principal] = certificate
	}

	return certificate, nil
}

func (h *hostCertificateCache) generateHostCert(principal string) (ssh.Signer, error) {
	keygen := native.New()
	defer keygen.Close()

	privBytes, pubBytes, err := keygen.GenerateKeyPair("")
	if err != nil {
		return nil, trace.Wrap(err)
	}

	clusterName, err := h.authService.GetDomainName()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	certBytes, err := h.authService.GenerateHostCert(pubBytes, principal, principal, clusterName, teleport.Roles{teleport.RoleNode}, 0)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	privateKey, err := ssh.ParsePrivateKey(privBytes)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	publicKey, _, _, _, err := ssh.ParseAuthorizedKey(certBytes)
	if err != nil {
		return nil, err
	}

	cert, ok := publicKey.(*ssh.Certificate)
	if !ok {
		return nil, trace.BadParameter("not a certificate")
	}

	s, err := ssh.NewCertSigner(cert, privateKey)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return s, nil
}
