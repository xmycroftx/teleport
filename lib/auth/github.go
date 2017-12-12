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

package auth

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/events"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/utils"

	"github.com/coreos/go-oidc/oauth2"
	"github.com/gravitational/trace"
	log "github.com/sirupsen/logrus"
)

func (s *AuthServer) CreateGithubAuthRequest(req services.GithubAuthRequest) (*services.GithubAuthRequest, error) {
	connector, err := s.Identity.GetGithubConnector(req.ConnectorID, true)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	client, err := s.getGithubOAuth2Client(connector)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	req.RedirectURL = client.AuthCodeURL(req.StateToken, "", "")
	req.StateToken, err = utils.CryptoRandomHex(TokenLenBytes)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	log.WithFields(log.Fields{trace.Component: "github"}).Debugf(
		"Redirect URL: %v", req.RedirectURL)
	err = s.Identity.CreateGithubAuthRequest(req, defaults.GithubAuthRequestTTL)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return &req, nil
}

type GithubAuthResponse struct {
	Username    string                     `json:"username"`
	Identity    services.ExternalIdentity  `json:"identity"`
	Session     services.WebSession        `json:"session,omitempty"`
	Cert        []byte                     `json:"cert,omitempty"`
	Req         services.GithubAuthRequest `json:"req"`
	HostSigners []services.CertAuthority   `json:"host_signers"`
}

func (s *AuthServer) ValidateGithubAuthCallback(q url.Values) (*GithubAuthResponse, error) {
	error := q.Get("error")
	if error != "" {
		return nil, trace.OAuth2(oauth2.ErrorInvalidRequest, error, q)
	}
	code := q.Get("code")
	if code == "" {
		return nil, trace.OAuth2(oauth2.ErrorInvalidRequest,
			"code query param must be set", q)
	}
	stateToken := q.Get("state")
	if stateToken == "" {
		return nil, trace.OAuth2(oauth2.ErrorInvalidRequest,
			"missing state query param", q)
	}
	req, err := s.Identity.GetGithubAuthRequest(stateToken)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	connector, err := s.Identity.GetGithubConnector(req.ConnectorID, true)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	client, err := s.getGithubOAuth2Client(connector)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	token, err := client.RequestToken(oauth2.GrantTypeAuthCode, code)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	claims, err := s.populateGithubClaims(token.AccessToken, connector.GetOrgs())
	if err != nil {
		return nil, trace.Wrap(err)
	}
	if len(connector.GetGroupsToRoles()) != 0 {
		err = s.createGithubUser(connector, *claims)
		if err != nil {
			return nil, trace.Wrap(err)
		}
	}
	response := &GithubAuthResponse{
		Identity: services.ExternalIdentity{
			ConnectorID: connector.GetName(),
			Username:    claims.Email,
		},
		Req: *req,
	}
	if !req.CheckUser {
		return response, nil
	}
	user, err := s.Identity.GetUserByGithubIdentity(response.Identity)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	response.Username = user.GetName()
	roles, err := services.FetchRoles(user.GetRoles(), s.Access, user.GetTraits())
	if err != nil {
		return nil, trace.Wrap(err)
	}
	if req.CreateWebSession {
		session, err := s.NewWebSession(user.GetName())
		if err != nil {
			return nil, trace.Wrap(err)
		}
		sessionTTL := roles.AdjustSessionTTL(defaults.WebSessionTTL)
		bearerTTL := utils.MinTTL(BearerTokenTTL, sessionTTL)
		session.SetExpiryTime(s.clock.Now().UTC().Add(sessionTTL))
		session.SetBearerTokenExpiryTime(s.clock.Now().UTC().Add(bearerTTL))
		err = s.UpsertWebSession(user.GetName(), session)
		if err != nil {
			return nil, trace.Wrap(err)
		}
	}
	if len(req.PublicKey) != 0 {
		allowedLogins, err := roles.CheckLoginDuration(
			roles.AdjustSessionTTL(req.CertTTL))
		if err != nil {
			return nil, trace.Wrap(err)
		}
		cert, err := s.GenerateUserCert(
			req.PublicKey,
			user,
			allowedLogins,
			req.CertTTL,
			roles.CanForwardAgents(),
			roles.CanPortForward(),
			req.Compatibility)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		response.Cert = cert
		authorities, err := s.GetCertAuthorities(services.HostCA, false)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		for _, authority := range authorities {
			response.HostSigners = append(response.HostSigners, authority)
		}
	}
	s.EmitAuditEvent(events.UserLoginEvent, events.EventFields{
		events.EventUser:   user.GetName(),
		events.LoginMethod: events.LoginMethodGithub,
	})
	return response, nil
}

func (s *AuthServer) createGithubUser(connector services.GithubConnector, claims githubClaims) error {
	roles := rolesFromClaims(connector, claims)
	log.WithFields(log.Fields{trace.Component: "github"}).Debugf(
		"Generating dynamic identity %v/%v with roles: %v",
		connector.GetName(), claims.Email, roles)
	user, err := services.GetUserMarshaler().GenerateUser(&services.UserV2{
		Kind:    services.KindUser,
		Version: services.V2,
		Metadata: services.Metadata{
			Name:      claims.Email,
			Namespace: defaults.Namespace,
		},
		Spec: services.UserSpecV2{
			Roles: roles,
			// Expires:        ident.ExpiresAt, ?? TODO
			GithubIdentities: []services.ExternalIdentity{
				{
					ConnectorID: connector.GetName(),
					Username:    claims.Email,
				},
			},
			CreatedBy: services.CreatedBy{
				User: services.UserRef{Name: "system"},
				Time: time.Now().UTC(),
				Connector: &services.ConnectorRef{
					Type:     teleport.ConnectorGithub,
					ID:       connector.GetName(),
					Identity: claims.Email,
				},
			},
		},
	})
	existingUser, err := s.GetUser(claims.Email)
	if err != nil && !trace.IsNotFound(err) {
		return trace.Wrap(err)
	}
	if existingUser != nil {
		ref := user.GetCreatedBy().Connector
		if !ref.IsSameProvider(existingUser.GetCreatedBy().Connector) {
			return trace.AlreadyExists("user %q already exists and is not Github user",
				existingUser.GetName())
		}
	}
	err = s.UpsertUser(user)
	if err != nil {
		return trace.Wrap(err)
	}
	return nil
}

func rolesFromClaims(connector services.GithubConnector, claims githubClaims) []string {
	var roles []string
	for _, mapping := range connector.GetGroupsToRoles() {
		teams, ok := claims.OrgToTeams[mapping.Organization]
		if !ok {
			// the user does not belong to this organization
			continue
		}
		for _, team := range teams {
			// see if the user belongs to this team
			if team == mapping.Group {
				roles = append(roles, mapping.Roles...)
			}
		}
	}
	return utils.Deduplicate(roles)
}

// githubClaims represents Github user information
type githubClaims struct {
	// Email is the user's primary email
	Email string
	// OrgToTeams is the user's organization and team membership
	OrgToTeams map[string][]string
}

func (s *AuthServer) populateGithubClaims(token string, orgs []string) (*githubClaims, error) {
	client := &githubAPIClient{token: token}
	// find the primary and verified email
	emails, err := client.getEmails()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	var primaryEmail string
	for _, email := range emails {
		if email.Primary && email.Verified {
			primaryEmail = email.Email
			break
		}
	}
	if primaryEmail == "" {
		return nil, trace.AccessDenied(
			"could not find primary verified email: %v", emails)
	}
	// build team memberships
	orgToTeams := make(map[string][]string)
	for _, org := range orgs {
		teams, err := client.getTeams(org)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		for _, team := range teams {
			orgToTeams[org] = append(orgToTeams[org], team.Slug)
		}
	}
	return &githubClaims{
		Email:      primaryEmail,
		OrgToTeams: orgToTeams,
	}, nil
}

func (s *AuthServer) getGithubOAuth2Client(connector services.GithubConnector) (*oauth2.Client, error) {
	s.lock.Lock()
	defer s.lock.Unlock()
	config := oauth2.Config{
		Credentials: oauth2.ClientCredentials{
			ID:     connector.GetClientID(),
			Secret: connector.GetClientSecret(),
		},
		RedirectURL: connector.GetRedirectURL(),
		Scope:       []string{"user:email", "read:org"},
		AuthURL:     "https://github.com/login/oauth/authorize",
		TokenURL:    "https://github.com/login/oauth/access_token",
	}
	cachedClient, ok := s.githubClients[connector.GetName()]
	if ok && oauth2ConfigsEqual(cachedClient.config, config) {
		return cachedClient.client, nil
	}
	delete(s.githubClients, connector.GetName())
	client, err := oauth2.NewClient(http.DefaultClient, config)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	s.githubClients[connector.GetName()] = &githubClient{
		client: client,
		config: config,
	}
	return client, nil
}

type githubAPIClient struct {
	token string
}

type emailsResponse struct {
	Email    string `json:"email"`
	Verified bool   `json:"verified"`
	Primary  bool   `json:"primary"`
}

func (c *githubAPIClient) getEmails() ([]emailsResponse, error) {
	bytes, err := c.get("https://api.github.com/user/emails")
	if err != nil {
		return nil, trace.Wrap(err)
	}
	var emails []emailsResponse
	err = json.Unmarshal(bytes, &emails)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return emails, nil
}

type teamsResponse struct {
	Name string `json:"name"`
	Slug string `json:"slug"`
}

func (c *githubAPIClient) getTeams(org string) ([]teamsResponse, error) {
	bytes, err := c.get(fmt.Sprintf("https://api.github.com/orgs/%v/teams", org))
	if err != nil {
		return nil, trace.Wrap(err)
	}
	var teams []teamsResponse
	err = json.Unmarshal(bytes, &teams)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return teams, nil
}

func (c *githubAPIClient) get(url string) ([]byte, error) {
	request, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	request.Header.Set("Authorization", fmt.Sprintf("token %v", c.token))
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return nil, trace.AccessDenied("bad response: %v",
			response.StatusCode)
	}
	return ioutil.ReadAll(response.Body)
}
