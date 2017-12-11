/*
Copyright 2016 Gravitational, Inc.

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
	"time"

	"golang.org/x/crypto/ssh/agent"

	"github.com/gravitational/teleport/lib/auth"
)

// RemoteSite represents remote teleport site that can be accessed via
// teleport tunnel or directly by proxy
//
// There are two implementations of this interface: local and remote sites.
type RemoteSite interface {
	// DialAuthServer returns a net.Conn to the Auth Server of a site.
	DialAuthServer() (net.Conn, error)
	// Dial dials any address within the site network.
	Dial(fromAddr, toAddr net.Addr, userAgent agent.Agent) (net.Conn, error)
	// GetLastConnected returns last time the remote site was seen connected
	GetLastConnected() time.Time
	// GetName returns site name (identified by authority domain's name)
	GetName() string
	// GetStatus returns status of this site (either offline or connected)
	GetStatus() string
	// GetClient returns client connected to remote auth server
	GetClient() (auth.ClientI, error)
	// CachingAccessPoint returns access point that is lightweight
	// but is resilient to auth server crashes
	CachingAccessPoint() (auth.AccessPoint, error)
}

// Server is a TCP/IP SSH server which listens on an SSH endpoint and remote/local
// sites connect and register with it.
type Server interface {
	// GetSites returns a list of connected remote sites
	GetSites() []RemoteSite
	// GetSite returns remote site this node belongs to
	GetSite(domainName string) (RemoteSite, error)
	// RemoveSite removes the site with the specified name from the list of connected sites
	RemoveSite(domainName string) error
	// Start starts server
	Start() error
	// CLose closes server's socket
	Close() error
	// Wait waits for server to close all outstanding operations
	Wait()
}
