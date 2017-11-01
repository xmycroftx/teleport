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
	"os"
	"time"

	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/auth/testauthority"
	"github.com/gravitational/teleport/lib/backend"
	"github.com/gravitational/teleport/lib/backend/boltbk"
	"github.com/gravitational/teleport/lib/backend/dir"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/utils"

	"github.com/jonboulle/clockwork"
	"gopkg.in/check.v1"
)

type CachePrimarySuite struct {
	dataDir    string
	backend    backend.Backend
	authServer *auth.AuthServer
	clock      clockwork.FakeClock
}

var _ = check.Suite(&CachePrimarySuite{})
var _ = fmt.Printf

func (s *CachePrimarySuite) SetUpSuite(c *check.C) {
	utils.InitLoggerForTests()

	// 11/10/2009 23:00 UTC
	frozenTime := time.Date(2009, time.November, 10, 23, 0, 0, 0, time.UTC)
	s.clock = clockwork.NewFakeClockAt(frozenTime)
}

func (s *CachePrimarySuite) TearDownSuite(c *check.C) {
}

func (s *CachePrimarySuite) SetUpTest(c *check.C) {
	// create a new auth server:
	s.dataDir = c.MkDir()
	var err error
	s.backend, err = boltbk.New(backend.Params{"path": s.dataDir})
	c.Assert(err, check.IsNil)

	clusterName, err := services.NewClusterName(services.ClusterNameSpecV2{
		ClusterName: "localhost",
	})
	c.Assert(err, check.IsNil)
	staticTokens, err := services.NewStaticTokens(services.StaticTokensSpecV2{
		StaticTokens: []services.ProvisionToken{},
	})
	c.Assert(err, check.IsNil)
	s.authServer = auth.NewAuthServer(&auth.InitConfig{
		Backend:      s.backend,
		Authority:    testauthority.New(),
		ClusterName:  clusterName,
		StaticTokens: staticTokens,
	})

	err = s.authServer.SetClusterName(clusterName)
	c.Assert(err, check.IsNil)

	// set cluster level configuration
	clusterConfig, err := services.NewClusterConfig(services.ClusterConfigSpecV3{
		SessionRecording: services.RecordAtProxy,
	})
	c.Assert(err, check.IsNil)
	err = s.authServer.SetClusterConfig(clusterConfig)
	c.Assert(err, check.IsNil)

	// set the namespace for cluster
	err = s.authServer.UpsertNamespace(
		services.NewNamespace(defaults.Namespace))
	c.Assert(err, check.IsNil)

	// add some nodes to it:
	for _, n := range Nodes {
		v2 := n.V2()
		v2.SetTTL(s.clock, defaults.ServerHeartbeatTTL)
		err = s.authServer.UpsertNode(v2)
		c.Assert(err, check.IsNil)
	}
	// add some proxies to it:
	for _, p := range Proxies {
		v2 := p.V2()
		v2.SetTTL(s.clock, defaults.ServerHeartbeatTTL)
		err = s.authServer.UpsertProxy(v2)
		c.Assert(err, check.IsNil)
	}
	// add some users to it:
	for _, u := range Users {
		v2 := u.V2()
		err = s.authServer.UpsertUser(v2)
		c.Assert(err, check.IsNil)
	}
	// add tunnel connections
	for _, c := range TunnelConnections {
		c.SetTTL(s.clock, defaults.ServerHeartbeatTTL)
		err = s.authServer.UpsertTunnelConnection(c)
	}

}

func (s *CachePrimarySuite) TearDownTest(c *check.C) {
	s.authServer.Close()
	s.backend.Close()
	os.RemoveAll(s.dataDir)
}

func (s *CachePrimarySuite) TestFetchAll(c *check.C) {
	cacheBackend, err := dir.New(backend.Params{"path": c.MkDir()})
	c.Assert(err, check.IsNil)

	// set clock on backend to a fake clock we control
	cacheBackend.(*dir.Backend).InternalClock = s.clock

	cachePrimary, err := NewCachePrimaryClient(Config{
		CacheTTL:    1 * time.Second,
		AccessPoint: s.authServer,
		Clock:       s.clock,
		Backend:     cacheBackend,
		SkipPreload: true,
	})
	c.Assert(err, check.IsNil)
	c.Assert(cachePrimary, check.NotNil)

	// make sure cache starts out empty
	users, err := cachePrimary.identity.GetUsers()
	c.Assert(err, check.NotNil)
	_, err = cachePrimary.presence.GetNodes(defaults.Namespace)
	c.Assert(err, check.NotNil)
	_, err = cachePrimary.presence.GetProxies()
	c.Assert(err, check.NotNil)
	_, err = cachePrimary.presence.GetTunnelConnections("example.com")
	c.Assert(err, check.NotNil)
}

func (s *CachePrimarySuite) TestCycle(c *check.C) {
	cacheBackend, err := dir.New(backend.Params{"path": c.MkDir()})
	c.Assert(err, check.IsNil)

	// set clock on backend to a fake clock we control
	cacheBackend.(*dir.Backend).InternalClock = s.clock

	cachePrimary, err := NewCachePrimaryClient(Config{
		CacheTTL:    1 * time.Second,
		AccessPoint: s.authServer,
		Clock:       s.clock,
		Backend:     cacheBackend,
		SkipPreload: true,
	})
	c.Assert(err, check.IsNil)
	c.Assert(cachePrimary, check.NotNil)

	// look in the cache first, we shouldn't have anything
	_, err = cachePrimary.config.GetClusterConfig()
	c.Assert(err, check.NotNil)

	// check in the primary cache. it should miss and then fetch it from the auth server.
	clusterConfig, err := cachePrimary.GetClusterConfig()
	c.Assert(err, check.IsNil)
	c.Assert(clusterConfig, check.NotNil)
	c.Assert(clusterConfig.GetSessionRecording(), check.Equals, services.RecordAtProxy)

	// now forward time, make sure we've expired the value in the cache
	s.clock.Advance(2 * time.Second)

	// look in the cache, it should be gone now
	clusterConfig, err = cachePrimary.config.GetClusterConfig()
	c.Assert(err, check.NotNil)

	// update it on the backend to a different value
	clusterConfig, err = services.NewClusterConfig(services.ClusterConfigSpecV3{
		SessionRecording: services.RecordOff,
	})
	c.Assert(err, check.IsNil)
	err = s.authServer.SetClusterConfig(clusterConfig)
	c.Assert(err, check.IsNil)

	// try getting it again, make sure it's been updated
	clusterConfig, err = cachePrimary.GetClusterConfig()
	c.Assert(err, check.IsNil)
	c.Assert(clusterConfig, check.NotNil)
	c.Assert(clusterConfig.GetSessionRecording(), check.Equals, services.RecordOff)
}
