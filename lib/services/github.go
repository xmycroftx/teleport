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

package services

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/utils"

	"github.com/gravitational/trace"
	"github.com/jonboulle/clockwork"
)

type GithubConnector interface {
	Resource
	CheckAndSetDefaults() error
	GetClientID() string
	SetClientID(string)
	GetClientSecret() string
	SetClientSecret(string)
	GetRedirectURL() string
	SetRedirectURL(string)
	GetTeamsToLogins() []TeamMapping
	SetTeamsToLogins([]TeamMapping)
	MapClaims(GithubClaims) []string
	GetOrgs() []string
	GetDisplay() string
	SetDisplay(string)
}

func NewGithubConnector(name string, spec GithubConnectorSpecV3) GithubConnector {
	return &GithubConnectorV3{
		Kind:    KindGithubConnector,
		Version: V3,
		Metadata: Metadata{
			Name:      name,
			Namespace: defaults.Namespace,
		},
		Spec: spec,
	}
}

type GithubConnectorV3 struct {
	// Kind is a resource kind, for Github connector it is "github"
	Kind string `json:"kind"`
	// Version is resource version
	Version string `json:"version"`
	// Metadata is resource metadata
	Metadata Metadata `json:"metadata"`
	// Spec contains connector specification
	Spec GithubConnectorSpecV3 `json:"spec"`
}

type GithubConnectorSpecV3 struct {
	ClientID      string        `json:"client_id"`
	ClientSecret  string        `json:"client_secret"`
	RedirectURL   string        `json:"redirect_url"`
	TeamsToLogins []TeamMapping `json:"teams_to_logins"`
	Display       string        `json:"display"`
}

type TeamMapping struct {
	Organization string   `json:"organization"`
	Team         string   `json:"team"`
	Logins       []string `json:"logins"`
}

// GithubClaims represents Github user information obtained during OAuth2 flow
type GithubClaims struct {
	// Email is the user's primary verified email
	Email string
	// OrganizationToTeams is the user's organization and team membership
	OrganizationToTeams map[string][]string
}

// GetName returns the name of the connector
func (c *GithubConnectorV3) GetName() string {
	return c.Metadata.GetName()
}

// SetName sets the connector name
func (c *GithubConnectorV3) SetName(name string) {
	c.Metadata.SetName(name)
}

// Expires returns the connector expiration time
func (c *GithubConnectorV3) Expiry() time.Time {
	return c.Metadata.Expiry()
}

// SetExpiry sets the connector expiration time
func (c *GithubConnectorV3) SetExpiry(expires time.Time) {
	c.Metadata.SetExpiry(expires)
}

// SetTTL sets the connector TTL
func (c *GithubConnectorV3) SetTTL(clock clockwork.Clock, ttl time.Duration) {
	c.Metadata.SetTTL(clock, ttl)
}

// GetMetadata returns the connector metadata
func (c *GithubConnectorV3) GetMetadata() Metadata {
	return c.Metadata
}

// CheckAndSetDefaults verifies the connector is valid and sets some defaults
func (c *GithubConnectorV3) CheckAndSetDefaults() error {
	if err := c.Metadata.CheckAndSetDefaults(); err != nil {
		return trace.Wrap(err)
	}
	return nil
}

func (c *GithubConnectorV3) GetClientID() string {
	return c.Spec.ClientID
}

func (c *GithubConnectorV3) SetClientID(id string) {
	c.Spec.ClientID = id
}

func (c *GithubConnectorV3) GetClientSecret() string {
	return c.Spec.ClientSecret
}

func (c *GithubConnectorV3) SetClientSecret(secret string) {
	c.Spec.ClientSecret = secret
}

func (c *GithubConnectorV3) GetRedirectURL() string {
	return c.Spec.RedirectURL
}

func (c *GithubConnectorV3) SetRedirectURL(redirectURL string) {
	c.Spec.RedirectURL = redirectURL
}

func (c *GithubConnectorV3) GetTeamsToLogins() []TeamMapping {
	return c.Spec.TeamsToLogins
}

func (c *GithubConnectorV3) SetTeamsToLogins(teamsToLogins []TeamMapping) {
	c.Spec.TeamsToLogins = teamsToLogins
}

func (c *GithubConnectorV3) GetOrgs() []string {
	var orgs []string
	for _, mapping := range c.Spec.TeamsToLogins {
		orgs = append(orgs, mapping.Organization)
	}
	return utils.Deduplicate(orgs)
}

func (c *GithubConnectorV3) GetDisplay() string {
	return c.Spec.Display
}

func (c *GithubConnectorV3) SetDisplay(display string) {
	c.Spec.Display = display
}

// MapClaims returns a list of logins based on the provided claims
func (c *GithubConnectorV3) MapClaims(claims GithubClaims) []string {
	var logins []string
	for _, mapping := range c.GetTeamsToLogins() {
		teams, ok := claims.OrganizationToTeams[mapping.Organization]
		if !ok {
			// the user does not belong to this organization
			continue
		}
		for _, team := range teams {
			// see if the user belongs to this team
			if team == mapping.Team {
				logins = append(logins, mapping.Logins...)
			}
		}
	}
	return utils.Deduplicate(logins)
}

var githubConnectorMarshaler GithubConnectorMarshaler = &TeleportGithubConnectorMarshaler{}

// SetGithubConnectorMarshaler sets Github connector marshaler
func SetGithubConnectorMarshaler(m GithubConnectorMarshaler) {
	marshalerMutex.Lock()
	defer marshalerMutex.Unlock()
	githubConnectorMarshaler = m
}

// GetGithubConnectorMarshaler returns currently set Github connector marshaler
func GetGithubConnectorMarshaler() GithubConnectorMarshaler {
	marshalerMutex.RLock()
	defer marshalerMutex.RUnlock()
	return githubConnectorMarshaler
}

// GithubConnectorMarshaler defines interface for Github connector marshaler
type GithubConnectorMarshaler interface {
	// Unmarshal unmarshals connector from binary representation
	Unmarshal(bytes []byte) (GithubConnector, error)
	// Marshal marshals connector to binary representation
	Marshal(c GithubConnector, opts ...MarshalOption) ([]byte, error)
}

// GetGithubConnectorSchema returns schema for Github connector
func GetGithubConnectorSchema() string {
	return fmt.Sprintf(GithubConnectorV3SchemaTemplate, MetadataSchema, GithubConnectorSpecV3Schema)
}

type TeleportGithubConnectorMarshaler struct{}

// UnmarshalGithubConnector unmarshals Github connector from JSON
func (*TeleportGithubConnectorMarshaler) Unmarshal(bytes []byte) (GithubConnector, error) {
	var h ResourceHeader
	if err := json.Unmarshal(bytes, &h); err != nil {
		return nil, trace.Wrap(err)
	}
	switch h.Version {
	case V3:
		var c GithubConnectorV3
		if err := utils.UnmarshalWithSchema(GetGithubConnectorSchema(), &c, bytes); err != nil {
			return nil, trace.Wrap(err)
		}
		if err := c.CheckAndSetDefaults(); err != nil {
			return nil, trace.Wrap(err)
		}
		return &c, nil
	}
	return nil, trace.BadParameter(
		"Github connector resource version %q is not supported", h.Version)
}

// MarshalGithubConnector marshals Github connector to JSON
func (*TeleportGithubConnectorMarshaler) Marshal(c GithubConnector, opts ...MarshalOption) ([]byte, error) {
	return json.Marshal(c)
}

const GithubConnectorV3SchemaTemplate = `{
  "type": "object",
  "additionalProperties": false,
  "required": ["kind", "spec", "metadata", "version"],
  "properties": {
    "kind": {"type": "string"},
    "version": {"type": "string", "default": "v3"},
    "metadata": %v,
    "spec": %v
  }
}`

var GithubConnectorSpecV3Schema = fmt.Sprintf(`{
  "type": "object",
  "additionalProperties": false,
  "required": ["client_id", "client_secret", "redirect_url"],
  "properties": {
    "client_id": {"type": "string"},
    "client_secret": {"type": "string"},
    "redirect_url": {"type": "string"},
    "display": {"type": "string"},
    "teams_to_logins": {
      "type": "array",
      "items": %v
    }
  }
}`, TeamMappingSchema)

var TeamMappingSchema = `{
  "type": "object",
  "additionalProperties": false,
  "required": ["organization", "team"],
  "properties": {
    "organization": {"type": "string"},
    "team": {"type": "string"},
    "logins": {
      "type": "array",
      "items": {
        "type": "string"
      }
    }
  }
}`
