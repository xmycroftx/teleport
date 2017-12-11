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

package regular

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/reversetunnel"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/srv"
	"github.com/gravitational/teleport/lib/sshutils"
	"github.com/gravitational/teleport/lib/utils"

	"github.com/gravitational/trace"
	log "github.com/sirupsen/logrus"
)

// proxySubsys implements an SSH subsystem for proxying listening sockets from
// remote hosts to a proxy client (AKA port mapping)
type proxySubsys struct {
	log          *log.Entry
	srv          *Server
	host         string
	port         string
	namespace    string
	clusterName  string
	closeC       chan struct{}
	error        error
	closeOnce    sync.Once
	agent        agent.Agent
	agentChannel ssh.Channel
}

// parseProxySubsys looks at the requested subsystem name and returns a fully configured
// proxy subsystem
//
// proxy subsystem name can take the following forms:
//  "proxy:host:22"          - standard SSH request to connect to  host:22 on the 1st cluster
//  "proxy:@clustername"        - Teleport request to connect to an auth server for cluster with name 'clustername'
//  "proxy:host:22@clustername" - Teleport request to connect to host:22 on cluster 'clustername'
//  "proxy:host:22@namespace@clustername"
func parseProxySubsys(request string, srv *Server, ctx *srv.ServerContext) (*proxySubsys, error) {
	log.Debugf("parse_proxy_subsys(%q)", request)
	var (
		clusterName  string
		targetHost   string
		targetPort   string
		paramMessage = fmt.Sprintf("invalid format for proxy request: %q, expected 'proxy:host:port@cluster'", request)
	)
	const prefix = "proxy:"
	// get rid of 'proxy:' prefix:
	if strings.Index(request, prefix) != 0 {
		return nil, trace.BadParameter(paramMessage)
	}
	requestBody := strings.TrimPrefix(request, prefix)
	namespace := defaults.Namespace
	var err error
	parts := strings.Split(requestBody, "@")
	switch {
	case len(parts) == 0: // "proxy:"
		return nil, trace.BadParameter(paramMessage)
	case len(parts) == 1: // "proxy:host:22"
		targetHost, targetPort, err = utils.SplitHostPort(parts[0])
		if err != nil {
			return nil, trace.BadParameter(paramMessage)
		}
	case len(parts) == 2: // "proxy:@clustername" or "proxy:host:22@clustername"
		if parts[0] != "" {
			targetHost, targetPort, err = utils.SplitHostPort(parts[0])
			if err != nil {
				return nil, trace.BadParameter(paramMessage)
			}
		}
		clusterName = parts[1]
		if clusterName == "" && targetHost == "" {
			return nil, trace.BadParameter("invalid format for proxy request: missing cluster name or target host in %q", request)
		}
	case len(parts) >= 3: // "proxy:host:22@namespace@clustername"
		clusterName = strings.Join(parts[2:], "@")
		namespace = parts[1]
		targetHost, targetPort, err = utils.SplitHostPort(parts[0])
		if err != nil {
			return nil, trace.BadParameter(paramMessage)
		}
	}
	if clusterName != "" && srv.proxyTun != nil {
		_, err := srv.proxyTun.GetSite(clusterName)
		if err != nil {
			return nil, trace.BadParameter("invalid format for proxy request: unknown cluster %q in %q", clusterName, request)
		}
	}

	return &proxySubsys{
		log: log.WithFields(log.Fields{
			trace.Component:       teleport.ComponentSubsystemProxy,
			trace.ComponentFields: map[string]string{},
		}),
		namespace:    namespace,
		srv:          srv,
		host:         targetHost,
		port:         targetPort,
		clusterName:  clusterName,
		closeC:       make(chan struct{}),
		agent:        ctx.GetAgent(),
		agentChannel: ctx.GetAgentChannel(),
	}, nil
}

func (t *proxySubsys) String() string {
	return fmt.Sprintf("proxySubsys(cluster=%s/%s, host=%s, port=%s)",
		t.namespace, t.clusterName, t.host, t.port)
}

// Start is called by Golang's ssh when it needs to engage this sybsystem (typically to establish
// a mapping connection between a client & remote node we're proxying to)
func (t *proxySubsys) Start(sconn *ssh.ServerConn, ch ssh.Channel, req *ssh.Request, ctx *srv.ServerContext) error {
	// once we start the connection, update logger to include component fields
	t.log = log.WithFields(log.Fields{
		trace.Component: teleport.ComponentSubsystemProxy,
		trace.ComponentFields: map[string]string{
			"src": sconn.RemoteAddr().String(),
			"dst": sconn.LocalAddr().String(),
		},
	})
	t.log.Debugf("Starting subsystem")

	var (
		site       reversetunnel.RemoteSite
		err        error
		tunnel     = t.srv.proxyTun
		clientAddr = sconn.RemoteAddr()
	)
	// did the client pass us a true client IP ahead of time via an environment variable?
	// (usually the web client would do that)
	ctx.Lock()
	trueClientIP, ok := ctx.GetEnv(sshutils.TrueClientAddrVar)
	ctx.Unlock()
	if ok {
		a, err := utils.ParseAddr(trueClientIP)
		if err == nil {
			clientAddr = a
		}
	}
	// get the cluster by name:
	if t.clusterName != "" {
		site, err = tunnel.GetSite(t.clusterName)
		if err != nil {
			t.log.Warn(err)
			return trace.Wrap(err)
		}
	}
	// connecting to a specific host:
	if t.host != "" {
		// no site given? use the 1st one:
		if site == nil {
			sites := tunnel.GetSites()
			if len(sites) == 0 {
				t.log.Errorf("Not connected to any remote clusters")
				return trace.Errorf("no connected sites")
			}
			site = sites[0]
			t.log.Debugf("Cluster not specified. connecting to default='%s'", site.GetName())
		}
		return t.proxyToHost(site, clientAddr, ch)
	}
	// connect to a site's auth server:
	return t.proxyToSite(site, clientAddr, ch)
}

// proxyToSite establishes a proxy connection from the connected SSH client to the
// auth server of the requested remote site
func (t *proxySubsys) proxyToSite(
	site reversetunnel.RemoteSite, remoteAddr net.Addr, ch ssh.Channel) error {

	conn, err := site.DialAuthServer()
	if err != nil {
		return trace.Wrap(err)
	}
	t.log.Infof("Connected to auth server: %v", conn.RemoteAddr())

	go func() {
		var err error
		defer func() {
			t.close(err)
		}()
		defer ch.Close()
		_, err = io.Copy(ch, conn)
	}()
	go func() {
		var err error
		defer func() {
			t.close(err)
		}()
		defer conn.Close()
		_, err = io.Copy(conn, ch)

	}()

	return nil
}

// proxyToHost establishes a proxy connection from the connected SSH client to the
// requested remote node (t.host:t.port) via the given site
func (t *proxySubsys) proxyToHost(
	site reversetunnel.RemoteSite, remoteAddr net.Addr, ch ssh.Channel) error {
	//
	// first, lets fetch a list of servers at the given site. this allows us to
	// match the given "host name" against node configuration (their 'nodename' setting)
	//
	// but failing to fetch the list of servers is also OK, we'll use standard
	// network resolution (by IP or DNS)
	//
	var (
		servers []services.Server
		err     error
	)
	localDomain, _ := t.srv.authService.GetDomainName()
	// going to "local" CA? lets use the caching 'auth service' directly and avoid
	// hitting the reverse tunnel link (it can be offline if the CA is down)
	if site.GetName() == localDomain {
		servers, err = t.srv.authService.GetNodes(t.namespace)
		if err != nil {
			t.log.Warn(err)
		}
	} else {
		// "remote" CA? use a reverse tunnel to talk to it:
		siteClient, err := site.CachingAccessPoint()
		if err != nil {
			t.log.Warn(err)
		} else {
			servers, err = siteClient.GetNodes(t.namespace)
			if err != nil {
				t.log.Warn(err)
			}
		}
	}

	// if port is 0, it means the client wants us to figure out
	// which port to use
	specifiedPort := len(t.port) > 0 && t.port != "0"
	ips, _ := net.LookupHost(t.host)
	t.log.Debugf("proxy connecting to host=%v port=%v, exact port=%v\n", t.host, t.port, specifiedPort)

	// enumerate and try to find a server with self-registered with a matching name/IP:
	var server services.Server
	for i := range servers {
		ip, port, err := net.SplitHostPort(servers[i].GetAddr())
		if err != nil {
			t.log.Error(err)
			continue
		}

		if t.host == ip || t.host == servers[i].GetHostname() || utils.SliceContainsStr(ips, ip) {
			if !specifiedPort || t.port == port {
				server = servers[i]
				break
			}
		}
	}

	var serverAddr string
	if server != nil {
		serverAddr = server.GetAddr()
	} else {
		if !specifiedPort {
			t.port = strconv.Itoa(defaults.SSHServerListenPort)
		}
		serverAddr = net.JoinHostPort(t.host, t.port)
		t.log.Warnf("server lookup failed: using default=%v", serverAddr)
	}

	// dial by IP address because the hostname may not be DNS resolvable
	// pass the agent along to the site (if the proxy is in recording mode, this
	// agent will be used for user auth)
	conn, err := site.Dial(
		remoteAddr,
		&utils.NetAddr{Addr: serverAddr, AddrNetwork: "tcp"},
		t.agent)
	if err != nil {
		return trace.Wrap(err)
	}

	// this custom SSH handshake allows SSH proxy to relay the client's IP
	// address to the SSH server
	t.doHandshake(remoteAddr, ch, conn)

	go func() {
		var err error
		defer func() {
			t.close(err)
		}()
		defer ch.Close()
		_, err = io.Copy(ch, conn)
	}()
	go func() {
		var err error
		defer func() {
			t.close(err)
		}()
		defer conn.Close()
		_, err = io.Copy(conn, ch)
	}()

	return nil
}

func (t *proxySubsys) close(err error) {
	t.closeOnce.Do(func() {
		t.error = err
		close(t.closeC)
	})
}

func (t *proxySubsys) Wait() error {
	<-t.closeC
	return t.error
}

// doHandshake allows a proxy server to send additional information (client IP)
// to an SSH server before establishing a bridge
func (t *proxySubsys) doHandshake(clientAddr net.Addr, clientConn io.ReadWriter, serverConn io.ReadWriter) {
	// on behalf of a client ask the server for it's version:
	buff := make([]byte, sshutils.MaxVersionStringBytes)
	n, err := serverConn.Read(buff)
	if err != nil {
		t.log.Error(err)
		return
	}
	// chop off extra unused bytes at the end of the buffer:
	buff = buff[:n]

	// is that a Teleport server?
	if bytes.HasPrefix(buff, []byte(sshutils.SSHVersionPrefix)) {
		// if we're connecting to a Teleport SSH server, send our own "handshake payload"
		// message, along with a client's IP:
		hp := &sshutils.HandshakePayload{
			ClientAddr: clientAddr.String(),
		}
		payloadJSON, err := json.Marshal(hp)
		if err != nil {
			t.log.Error(err)
		} else {
			// send a JSON payload sandwitched between 'teleport proxy signature' and 0x00:
			payload := fmt.Sprintf("%s%s\x00", sshutils.ProxyHelloSignature, payloadJSON)
			n, err = serverConn.Write([]byte(payload))
			if err != nil {
				t.log.Error(err)
			}
		}
	}
	// forwrd server's response to the client:
	_, err = clientConn.Write(buff)
	if err != nil {
		t.log.Error(err)
	}
}
