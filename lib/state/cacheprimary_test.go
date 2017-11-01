package state

import (
	"fmt"
	"os"

	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/auth/testauthority"
	"github.com/gravitational/teleport/lib/backend"
	"github.com/gravitational/teleport/lib/backend/boltbk"
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
	clock      clockwork.Clock
}

var _ = check.Suite(&CachePrimarySuite{})
var _ = fmt.Printf

func (s *CachePrimarySuite) SetUpSuite(c *check.C) {
	utils.InitLoggerForTests()
	s.clock = clockwork.NewRealClock()
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

func (s *CachePrimarySuite) TestCycle(c *check.C) {
}
