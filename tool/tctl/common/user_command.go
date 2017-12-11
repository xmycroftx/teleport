/*
Copyright 2015-2017 Gravitational, Inc.

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

package common

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/gravitational/kingpin"
	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/lib/asciitable"
	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/service"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/web"
	"github.com/gravitational/trace"
)

// UserCommand implements `tctl users` set of commands
// It implements CLICommand interface
type UserCommand struct {
	config        *service.Config
	login         string
	allowedLogins string
	roles         string
	identities    []string
	ttl           time.Duration

	userAdd    *kingpin.CmdClause
	userUpdate *kingpin.CmdClause
	userList   *kingpin.CmdClause
	userDelete *kingpin.CmdClause
}

// Initialize allows UserCommand to plug itself into the CLI parser
func (u *UserCommand) Initialize(app *kingpin.Application, config *service.Config) {
	u.config = config
	users := app.Command("users", "Manage user accounts")

	u.userAdd = users.Command("add", "Generate a user invitation token")
	u.userAdd.Arg("account", "Teleport user account name").Required().StringVar(&u.login)
	u.userAdd.Arg("local-logins", "Local UNIX users this account can log in as [login]").
		Default("").StringVar(&u.allowedLogins)
	u.userAdd.Flag("ttl", fmt.Sprintf("Set expiration time for token, default is %v hour, maximum is %v hours",
		int(defaults.SignupTokenTTL/time.Hour), int(defaults.MaxSignupTokenTTL/time.Hour))).
		Default(fmt.Sprintf("%v", defaults.SignupTokenTTL)).DurationVar(&u.ttl)
	u.userAdd.Alias(AddUserHelp)

	u.userUpdate = users.Command("update", "Update properties for existing user").Hidden()
	u.userUpdate.Arg("login", "Teleport user login").Required().StringVar(&u.login)
	u.userUpdate.Flag("set-roles", "Roles to assign to this user").
		Default("").StringVar(&u.roles)

	u.userList = users.Command("ls", "List all user accounts")

	u.userDelete = users.Command("rm", "Deletes user accounts").Alias("del")
	u.userDelete.Arg("logins", "Comma-separated list of user logins to delete").
		Required().StringVar(&u.login)
}

// TryRun takes the CLI command as an argument (like "users add") and executes it.
func (u *UserCommand) TryRun(cmd string, client *auth.TunClient) (match bool, err error) {
	switch cmd {
	case u.userAdd.FullCommand():
		err = u.Add(client)
	case u.userUpdate.FullCommand():
		err = u.Update(client)
	case u.userList.FullCommand():
		err = u.List(client)
	case u.userDelete.FullCommand():
		err = u.Delete(client)
	default:
		return false, nil
	}
	return true, trace.Wrap(err)
}

// Add creates a new sign-up token and prints a token URL to stdout.
// A user is not created until he visits the sign-up URL and completes the process
func (u *UserCommand) Add(client *auth.TunClient) error {
	// if no local logins were specified, default to 'login'
	if u.allowedLogins == "" {
		u.allowedLogins = u.login
	}
	user := services.UserV1{
		Name:          u.login,
		AllowedLogins: strings.Split(u.allowedLogins, ","),
	}
	token, err := client.CreateSignupToken(user, u.ttl)
	if err != nil {
		return err
	}

	// try to auto-suggest the activation link
	u.PrintSignupURL(client, token, u.ttl)
	return nil
}

func (u *UserCommand) PrintSignupURL(client *auth.TunClient, token string, ttl time.Duration) {
	hostname := "your.teleport.proxy"

	proxies, err := client.GetProxies()
	if err == nil {
		if len(proxies) == 0 {
			fmt.Printf("\x1b[1mWARNING\x1b[0m: this Teleport cluster does not have any proxy servers online.\nYou need to start some to be able to login.\n\n")
		} else {
			hostname = proxies[0].GetHostname()
		}
	}
	_, proxyPort, err := net.SplitHostPort(u.config.Proxy.WebAddr.Addr)
	if err != nil {
		proxyPort = strconv.Itoa(defaults.HTTPListenPort)
	}
	url := web.CreateSignupLink(net.JoinHostPort(hostname, proxyPort), token)
	fmt.Printf("Signup token has been created and is valid for %v hours. Share this URL with the user:\n%v\n\nNOTE: make sure '%s' is accessible!\n",
		int(ttl/time.Hour), url, hostname)
}

// Update updates existing user
func (u *UserCommand) Update(client *auth.TunClient) error {
	user, err := client.GetUser(u.login)
	if err != nil {
		return trace.Wrap(err)
	}
	roles := strings.Split(u.roles, ",")
	for _, role := range roles {
		if _, err := client.GetRole(role); err != nil {
			return trace.Wrap(err)
		}
	}
	user.SetRoles(roles)
	if err := client.UpsertUser(user); err != nil {
		return trace.Wrap(err)
	}
	fmt.Printf("%v has been updated with roles %v\n", user.GetName(), strings.Join(user.GetRoles(), ","))
	return nil
}

// List prints all existing user accounts
func (u *UserCommand) List(client *auth.TunClient) error {
	users, err := client.GetUsers()
	if err != nil {
		return trace.Wrap(err)
	}
	if len(users) == 0 {
		fmt.Println("No users found")
		return nil
	}
	t := asciitable.MakeTable([]string{"User", "Allowed logins"})
	for _, u := range users {
		logins, _ := u.GetTraits()[teleport.TraitLogins]
		t.AddRow([]string{u.GetName(), strings.Join(logins, ",")})
	}
	fmt.Println(t.AsBuffer().String())
	return nil
}

// Delete deletes teleport user(s). User IDs are passed as a comma-separated
// list in UserCommand.login
func (u *UserCommand) Delete(client *auth.TunClient) error {
	for _, l := range strings.Split(u.login, ",") {
		if err := client.DeleteUser(l); err != nil {
			return trace.Wrap(err)
		}
		fmt.Printf("User '%v' has been deleted\n", l)
	}
	return nil
}
