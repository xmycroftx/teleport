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
	GetGroupsToRoles() []GroupMapping
	SetGroupsToRoles([]GroupMapping)
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
	ClientID      string         `json:"client_id"`
	ClientSecret  string         `json:"client_secret"`
	RedirectURL   string         `json:"redirect_url"`
	GroupsToRoles []GroupMapping `json:"groups_to_roles"`
}

type GroupMapping struct {
	Organization string   `json:"organization"`
	Group        string   `json:"group"`
	Roles        []string `json:"roles"`
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

func (c *GithubConnectorV3) GetGroupsToRoles() []GroupMapping {
	return c.Spec.GroupsToRoles
}

func (c *GithubConnectorV3) SetGroupsToRoles(groupsToRoles []GroupMapping) {
	c.Spec.GroupsToRoles = groupsToRoles
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
    "groups_to_roles": {
      "type": "array",
      "items": %v
    }
  }
}`, GroupMappingSchema)

var GroupMappingSchema = `{
  "type": "object",
  "additionalProperties": false,
  "required": ["organization", "group"],
  "properties": {
    "organization": {"type": "string"},
    "group": {"type": "string"},
    "roles": {
      "type": "array",
      "items": {
        "type": "string"
      }
    }
  }
}`
