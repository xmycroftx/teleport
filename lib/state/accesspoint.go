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
	"time"

	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/backend"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/utils"

	"github.com/gravitational/trace"
	"github.com/jonboulle/clockwork"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	accessPointRequests = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "access_point_requests",
			Help: "Number of access point requests",
		},
	)
)

func init() {
	// Metrics have to be registered to be exposed:
	prometheus.MustRegister(accessPointRequests)
}

// Config is CachingAuthClient config
type Config struct {
	// CacheTTL sets maximum TTL the cache keeps the value
	CacheTTL time.Duration
	// NeverExpires if set, never expires cache values
	NeverExpires bool
	// AccessPoint is access point for this
	AccessPoint auth.AccessPoint
	// Backend is cache backend
	Backend backend.Backend
	// Clock can be set to control time
	Clock clockwork.Clock
	// SkipPreload turns off preloading on start
	SkipPreload bool
	// Policy specifies the caching policy to use.
	Policy CachePolicy
}

// CachePolicy holds different policy types.
type CachePolicy string

var (
	// CachePrimary makes requests to the cache before making requests to the
	// Auth Server.
	CachePrimary CachePolicy = "cache_primary"

	// CacheSecondary makes requests to the cache after requests to the Auth
	// Server fail.
	CacheSecondary CachePolicy = "cache_secondary"
)

// CheckAndSetDefaults checks parameters and sets default values
func (c *Config) CheckAndSetDefaults() error {
	if !c.NeverExpires && c.CacheTTL == 0 {
		c.CacheTTL = defaults.CacheTTL
	}
	if c.AccessPoint == nil {
		return trace.BadParameter("missing AccessPoint parameter")
	}
	if c.Backend == nil {
		return trace.BadParameter("missing Backend parameter")
	}
	if c.Clock == nil {
		c.Clock = clockwork.NewRealClock()
	}
	if !utils.SliceContainsStr([]string{string(CachePrimary), string(CacheSecondary)}, string(c.Policy)) {
		return trace.BadParameter("unknown policy %v", c.Policy)
	}
	return nil
}

// NewCachingAuthClient creates a new instance of CachingAuthClient using a
// live connection to the auth server (ap)
func NewCachingAuthClient(config Config) (auth.AccessPoint, error) {
	if err := config.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}

	switch config.Policy {
	//case CachePrimary:
	//	return NewCacheSecondaryClient(config)
	case CacheSecondary:
		return NewCacheSecondaryClient(config)
	}

	return nil, trace.BadParameter("unknown policy %v", config.Policy)
}
