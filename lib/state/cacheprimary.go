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

package state

import (
	"fmt"
	"time"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/services/local"

	"github.com/gravitational/trace"
	log "github.com/sirupsen/logrus"
)

// cachePrimaryClient implements auth.AccessPoint interface and consults
// cache first before making a request to the Auth Server.
type cachePrimaryClient struct {
	*log.Entry

	// Config is the configuration for cachePrimaryClient.
	Config

	// ap is the access point we're caching access to.
	ap auth.AccessPoint

	// lastErrorTime is a timestamp of the last error when talking to the AP
	lastErrorTime time.Time

	identity services.Identity
	access   services.Access
	trust    services.Trust
	presence services.Presence
	config   services.ClusterConfiguration
}

// NewCachePrimaryClient creates a new instance of cachePrimaryClient which
// first consults in-memory cache and updates upon misses.
func NewCachePrimaryClient(config Config) (*cachePrimaryClient, error) {
	cs := &cachePrimaryClient{
		Config:   config,
		ap:       config.AccessPoint,
		identity: local.NewIdentityService(config.Backend),
		trust:    local.NewCAService(config.Backend),
		access:   local.NewAccessService(config.Backend),
		presence: local.NewPresenceService(config.Backend),
		config:   local.NewClusterConfigurationService(config.Backend),
		Entry: log.WithFields(log.Fields{
			trace.Component: teleport.ComponentCachingClient,
		}),
	}
	if !cs.SkipPreload {
		err := cs.fetchAll()
		if err != nil {
			// we almost always get some "access denied" errors here because
			// not all cacheable resources are available (for example nodes do
			// not have access to tunnels)
			cs.Debugf("auth cache (primary): %v", err)
		}
	}
	return cs, nil
}

func (cs *cachePrimaryClient) fetchAll() error {
	return nil
	//	var errors []error
	//	_, err := cs.GetDomainName()
	//	errors = append(errors, err)
	//	_, err = cs.GetClusterConfig()
	//	errors = append(errors, err)
	//	_, err = cs.GetRoles()
	//	errors = append(errors, err)
	//	namespaces, err := cs.GetNamespaces()
	//	errors = append(errors, err)
	//	if err == nil {
	//		for _, ns := range namespaces {
	//			_, err = cs.GetNodes(ns.Metadata.Name)
	//			errors = append(errors, err)
	//		}
	//	}
	//	_, err = cs.GetProxies()
	//	errors = append(errors, err)
	//	_, err = cs.GetReverseTunnels()
	//	errors = append(errors, err)
	//	_, err = cs.GetCertAuthorities(services.UserCA, false)
	//	errors = append(errors, err)
	//	_, err = cs.GetCertAuthorities(services.HostCA, false)
	//	errors = append(errors, err)
	//	_, err = cs.GetUsers()
	//	errors = append(errors, err)
	//	conns, err := cs.ap.GetAllTunnelConnections()
	//	if err != nil {
	//		errors = append(errors, err)
	//	}
	//	clusters := map[string]bool{}
	//	for _, conn := range conns {
	//		clusterName := conn.GetClusterName()
	//		if _, ok := clusters[clusterName]; ok {
	//			continue
	//		}
	//		clusters[clusterName] = true
	//		_, err = cs.GetTunnelConnections(clusterName)
	//		errors = append(errors, err)
	//	}
	//	return trace.NewAggregate(errors...)
}

//// GetDomainName is a part of auth.AccessPoint implementation
//func (cs *cachePrimaryClient) GetDomainName() (clusterName string, err error) {
//	err = cs.try(func() error {
//		clusterName, err = cs.ap.GetDomainName()
//		return err
//	})
//	if err != nil {
//		if trace.IsConnectionProblem(err) {
//			return cs.presence.GetLocalClusterName()
//		}
//		return clusterName, err
//	}
//	if err = cs.presence.UpsertLocalClusterName(clusterName); err != nil {
//		return "", trace.Wrap(err)
//	}
//	return clusterName, err
//}

func (cs *cachePrimaryClient) GetClusterConfig() (clusterConfig services.ClusterConfig, err error) {
	clusterConfig, err = cs.ap.GetClusterConfig()
	if err != nil {
		err = cs.try(func() error {
			clusterConfig, err = cs.ap.GetClusterConfig()
			return err
		})
		if err != nil {
			return nil, trace.Wrap(err)
		}

		// set ttl upsert resource. we do this so we periodically update cache.
		cs.setTTL(clusterConfig)
		err = cs.config.SetClusterConfig(clusterConfig)
		if err != nil {
			return nil, trace.Wrap(err)
		}
	}

	return clusterConfig, nil

	//err = cs.try(func() error {
	//	clusterConfig, err = cs.ap.GetClusterConfig()
	//	return err
	//})
	//if err != nil {
	//	if trace.IsConnectionProblem(err) {
	//		return cs.config.GetClusterConfig()
	//	}
	//	return nil, trace.Wrap(err)
	//}
	//if err = cs.config.SetClusterConfig(clusterConfig); err != nil {
	//	return nil, trace.Wrap(err)
	//}
	//return clusterConfig, nil
}

//// GetRoles is a part of auth.AccessPoint implementation
//func (cs *cachePrimaryClient) GetRoles() (roles []services.Role, err error) {
//	err = cs.try(func() error {
//		roles, err = cs.ap.GetRoles()
//		return err
//	})
//	if err != nil {
//		if trace.IsConnectionProblem(err) {
//			return cs.access.GetRoles()
//		}
//		return roles, err
//	}
//	if err := cs.access.DeleteAllRoles(); err != nil {
//		if !trace.IsNotFound(err) {
//			return nil, trace.Wrap(err)
//		}
//	}
//	for _, role := range roles {
//		if err := cs.access.UpsertRole(role, backend.Forever); err != nil {
//			return nil, trace.Wrap(err)
//		}
//	}
//	return roles, err
//}
//
//// GetRole is a part of auth.AccessPoint implementation
//func (cs *cachePrimaryClient) GetRole(name string) (role services.Role, err error) {
//	err = cs.try(func() error {
//		role, err = cs.ap.GetRole(name)
//		return err
//	})
//	if err != nil {
//		if trace.IsConnectionProblem(err) {
//			return cs.access.GetRole(name)
//		}
//		return role, err
//	}
//	if err := cs.access.DeleteRole(name); err != nil {
//		if !trace.IsNotFound(err) {
//			return nil, trace.Wrap(err)
//		}
//	}
//	cs.setTTL(role)
//	if err := cs.access.UpsertRole(role, backend.Forever); err != nil {
//		return nil, trace.Wrap(err)
//	}
//	return role, nil
//}
//
//// GetNamespace returns namespace
//func (cs *cachePrimaryClient) GetNamespace(name string) (namespace *services.Namespace, err error) {
//	err = cs.try(func() error {
//		namespace, err = cs.ap.GetNamespace(name)
//		return err
//	})
//	if err != nil {
//		if trace.IsConnectionProblem(err) {
//			return cs.presence.GetNamespace(name)
//		}
//		return namespace, err
//	}
//	if err := cs.presence.DeleteNamespace(name); err != nil {
//		if !trace.IsNotFound(err) {
//			return nil, trace.Wrap(err)
//		}
//	}
//	if err := cs.presence.UpsertNamespace(*namespace); err != nil {
//		return nil, trace.Wrap(err)
//	}
//	return namespace, err
//}
//
//// GetNamespaces is a part of auth.AccessPoint implementation
//func (cs *cachePrimaryClient) GetNamespaces() (namespaces []services.Namespace, err error) {
//	err = cs.try(func() error {
//		namespaces, err = cs.ap.GetNamespaces()
//		return err
//	})
//
//	if err != nil {
//		if trace.IsConnectionProblem(err) {
//			return cs.presence.GetNamespaces()
//		}
//		return namespaces, err
//	}
//	if err := cs.presence.DeleteAllNamespaces(); err != nil {
//		if !trace.IsNotFound(err) {
//			return nil, trace.Wrap(err)
//		}
//	}
//	for _, ns := range namespaces {
//		if err := cs.presence.UpsertNamespace(ns); err != nil {
//			return nil, trace.Wrap(err)
//		}
//	}
//	return namespaces, err
//}
//
//// GetNodes is a part of auth.AccessPoint implementation
//func (cs *cachePrimaryClient) GetNodes(namespace string) (nodes []services.Server, err error) {
//	err = cs.try(func() error {
//		nodes, err = cs.ap.GetNodes(namespace)
//		return err
//
//	})
//	if err != nil {
//		if trace.IsConnectionProblem(err) {
//			return cs.presence.GetNodes(namespace)
//		}
//		return nodes, err
//	}
//	if err := cs.presence.DeleteAllNodes(namespace); err != nil {
//		if !trace.IsNotFound(err) {
//			return nil, trace.Wrap(err)
//		}
//	}
//	for _, node := range nodes {
//		cs.setTTL(node)
//		if err := cs.presence.UpsertNode(node); err != nil {
//			return nil, trace.Wrap(err)
//		}
//	}
//	return nodes, err
//}
//
//func (cs *cachePrimaryClient) GetReverseTunnels() (tunnels []services.ReverseTunnel, err error) {
//	err = cs.try(func() error {
//		tunnels, err = cs.ap.GetReverseTunnels()
//		return err
//	})
//	if err != nil {
//		if trace.IsConnectionProblem(err) {
//			return cs.presence.GetReverseTunnels()
//		}
//		return tunnels, err
//	}
//	if err := cs.presence.DeleteAllReverseTunnels(); err != nil {
//		if !trace.IsNotFound(err) {
//			return nil, trace.Wrap(err)
//		}
//	}
//	for _, tunnel := range tunnels {
//		cs.setTTL(tunnel)
//		if err := cs.presence.UpsertReverseTunnel(tunnel); err != nil {
//			return nil, trace.Wrap(err)
//		}
//	}
//	return tunnels, err
//}
//
//// GetProxies is a part of auth.AccessPoint implementation
//func (cs *cachePrimaryClient) GetProxies() (proxies []services.Server, err error) {
//	err = cs.try(func() error {
//		proxies, err = cs.ap.GetProxies()
//		return err
//	})
//
//	if err != nil {
//		if trace.IsConnectionProblem(err) {
//			return cs.presence.GetProxies()
//		}
//		return proxies, err
//	}
//	if err := cs.presence.DeleteAllProxies(); err != nil {
//		if !trace.IsNotFound(err) {
//			return nil, trace.Wrap(err)
//		}
//	}
//	for _, proxy := range proxies {
//		cs.setTTL(proxy)
//		if err := cs.presence.UpsertProxy(proxy); err != nil {
//			return nil, trace.Wrap(err)
//		}
//	}
//	return proxies, err
//}
//
//// GetCertAuthorities is a part of auth.AccessPoint implementation
//func (cs *cachePrimaryClient) GetCertAuthorities(ct services.CertAuthType, loadKeys bool) (cas []services.CertAuthority, err error) {
//	err = cs.try(func() error {
//		cas, err = cs.ap.GetCertAuthorities(ct, loadKeys)
//		return err
//	})
//	if err != nil {
//		if trace.IsConnectionProblem(err) {
//			return cs.trust.GetCertAuthorities(ct, loadKeys)
//		}
//		return cas, err
//	}
//	if err := cs.trust.DeleteAllCertAuthorities(ct); err != nil {
//		if !trace.IsNotFound(err) {
//			return nil, trace.Wrap(err)
//		}
//	}
//	for _, ca := range cas {
//		cs.setTTL(ca)
//		if err := cs.trust.UpsertCertAuthority(ca); err != nil {
//			return nil, trace.Wrap(err)
//		}
//	}
//	return cas, err
//}
//
//// GetUsers is a part of auth.AccessPoint implementation
//func (cs *cachePrimaryClient) GetUsers() (users []services.User, err error) {
//	err = cs.try(func() error {
//		users, err = cs.ap.GetUsers()
//		return err
//	})
//	if err != nil {
//		if trace.IsConnectionProblem(err) {
//			return cs.identity.GetUsers()
//		}
//		return users, err
//	}
//	if err := cs.identity.DeleteAllUsers(); err != nil {
//		if !trace.IsNotFound(err) {
//			return nil, trace.Wrap(err)
//		}
//	}
//	for _, user := range users {
//		cs.setTTL(user)
//		if err := cs.identity.UpsertUser(user); err != nil {
//			return nil, trace.Wrap(err)
//		}
//	}
//	return users, err
//}
//
//// GetTunnelConnections is a part of auth.AccessPoint implementation
//func (cs *cachePrimaryClient) GetTunnelConnections(clusterName string) (conns []services.TunnelConnection, err error) {
//	err = cs.try(func() error {
//		conns, err = cs.ap.GetTunnelConnections(clusterName)
//		return err
//	})
//	if err != nil {
//		if trace.IsConnectionProblem(err) {
//			return cs.presence.GetTunnelConnections(clusterName)
//		}
//		return conns, err
//	}
//	if err := cs.presence.DeleteTunnelConnections(clusterName); err != nil {
//		if !trace.IsNotFound(err) {
//			return nil, trace.Wrap(err)
//		}
//	}
//	for _, conn := range conns {
//		cs.setTTL(conn)
//		if err := cs.presence.UpsertTunnelConnection(conn); err != nil {
//			return nil, trace.Wrap(err)
//		}
//	}
//	return conns, err
//}
//
//// GetAllTunnelConnections is a part of auth.AccessPoint implementation
//func (cs *cachePrimaryClient) GetAllTunnelConnections() (conns []services.TunnelConnection, err error) {
//	err = cs.try(func() error {
//		conns, err = cs.ap.GetAllTunnelConnections()
//		return err
//	})
//	if err != nil {
//		if trace.IsConnectionProblem(err) {
//			return cs.presence.GetAllTunnelConnections()
//		}
//		return conns, err
//	}
//	if err := cs.presence.DeleteAllTunnelConnections(); err != nil {
//		if !trace.IsNotFound(err) {
//			return nil, trace.Wrap(err)
//		}
//	}
//	for _, conn := range conns {
//		cs.setTTL(conn)
//		if err := cs.presence.UpsertTunnelConnection(conn); err != nil {
//			return nil, trace.Wrap(err)
//		}
//	}
//	return conns, err
//}
//
//// UpsertNode is part of auth.AccessPoint implementation
//func (cs *cachePrimaryClient) UpsertNode(s services.Server) error {
//	cs.setTTL(s)
//	return cs.ap.UpsertNode(s)
//}
//
//// UpsertProxy is part of auth.AccessPoint implementation
//func (cs *cachePrimaryClient) UpsertProxy(s services.Server) error {
//	cs.setTTL(s)
//	return cs.ap.UpsertProxy(s)
//}
//
//// UpsertTunnelConnection is a part of auth.AccessPoint implementation
//func (cs *cachePrimaryClient) UpsertTunnelConnection(conn services.TunnelConnection) error {
//	cs.setTTL(conn)
//	return cs.ap.UpsertTunnelConnection(conn)
//}
//
//// DeleteTunnelConnection is a part of auth.AccessPoint implementation
//func (cs *cachePrimaryClient) DeleteTunnelConnection(clusterName, connName string) error {
//	return cs.ap.DeleteTunnelConnection(clusterName, connName)
//}

// try calls a given function f and checks for errors. If f() fails, the current
// time is recorded. Future calls to f will be ingored until sufficient time passes
// since th last error
func (cs *cachePrimaryClient) try(f func() error) error {
	tooSoon := cs.lastErrorTime.Add(defaults.NetworkRetryDuration).After(time.Now())
	if tooSoon {
		cs.Warnf("backoff: using cached value due to recent errors")
		return trace.ConnectionProblem(fmt.Errorf("backoff"), "backing off due to recent errors")
	}
	accessPointRequests.Inc()
	err := trace.ConvertSystemError(f())
	if trace.IsConnectionProblem(err) {
		cs.lastErrorTime = time.Now()
		cs.Warningf("connection problem: failed connect to the auth servers, using local cache")
	}
	return err
}

func (cs *cachePrimaryClient) setTTL(r services.Resource) {
	if cs.NeverExpires {
		return
	}
	// honor expiry set by user
	if !r.Expiry().IsZero() {
		return
	}
	// set TTL as a global setting
	r.SetTTL(cs.Clock, cs.CacheTTL)
}