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
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/lib/config"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/service"
	"github.com/gravitational/teleport/lib/sshutils/scp"
	"github.com/gravitational/teleport/lib/utils"

	"github.com/google/gops/agent"
	"github.com/gravitational/roundtrip"
	"github.com/gravitational/trace"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
)

// Options combines init/start teleport options
type Options struct {
	// Args is a list of command-line args passed from main()
	Args []string
	// InitOnly when set to true, initializes config and aux
	// endpoints but does not start the process
	InitOnly bool
}

// Run inits/starts the process according to the provided options
func Run(options Options) (executedCommand string, conf *service.Config) {
	var err error

	// configure trace's errors to produce full stack traces
	isDebug, _ := strconv.ParseBool(os.Getenv(teleport.VerboseLogsEnvVar))
	if isDebug {
		trace.SetDebug(true)
	}
	// configure logger for a typical CLI scenario until configuration file is
	// parsed
	utils.InitLogger(utils.LoggingForDaemon, log.WarnLevel)
	app := utils.InitCLIParser("teleport", "Clustered SSH service. Learn more at https://gravitational.com/teleport")

	// define global flags:
	var ccf config.CommandLineFlags
	var scpCommand scp.Command

	// define commands:
	start := app.Command("start", "Starts the Teleport service.")
	status := app.Command("status", "Print the status of the current SSH session.")
	dump := app.Command("configure", "Print the sample config file into stdout.")
	ver := app.Command("version", "Print the version.")
	scpc := app.Command("scp", "server-side implementation of scp").Hidden()
	app.HelpFlag.Short('h')

	// define start flags:
	start.Flag("debug", "Enable verbose logging to stderr").
		Short('d').
		BoolVar(&ccf.Debug)
	start.Flag("insecure-no-tls", "Disable TLS for the web socket").
		BoolVar(&ccf.DisableTLS)
	start.Flag("roles",
		fmt.Sprintf("Comma-separated list of roles to start with [%s]", strings.Join(defaults.StartRoles, ","))).
		Short('r').
		StringVar(&ccf.Roles)
	start.Flag("pid-file",
		"Full path to the PID file. By default no PID file will be created").StringVar(&ccf.PIDFile)
	start.Flag("advertise-ip",
		"IP to advertise to clients if running behind NAT").
		IPVar(&ccf.AdvertiseIP)
	start.Flag("listen-ip",
		fmt.Sprintf("IP address to bind to [%s]", defaults.BindIP)).
		Short('l').
		IPVar(&ccf.ListenIP)
	start.Flag("auth-server",
		fmt.Sprintf("Address of the auth server [%s]", defaults.AuthConnectAddr().Addr)).
		StringVar(&ccf.AuthServerAddr)
	start.Flag("token",
		"One-time token to register with an auth server [none]").
		StringVar(&ccf.AuthToken)
	start.Flag("nodename",
		"Name of this node, defaults to hostname").
		StringVar(&ccf.NodeName)
	start.Flag("config",
		fmt.Sprintf("Path to a configuration file [%v]", defaults.ConfigFilePath)).
		Short('c').ExistingFileVar(&ccf.ConfigFile)
	start.Flag("config-string",
		"Base64 encoded configuration string").Hidden().Envar(defaults.ConfigEnvar).
		StringVar(&ccf.ConfigString)
	start.Flag("labels", "List of labels for this node").StringVar(&ccf.Labels)
	start.Flag("httpprofile",
		"[DEPRECATED] Start profiling endpoint on localhost:6060").Hidden().BoolVar(&ccf.HTTPProfileEndpoint)
	start.Flag("gops",
		"Start gops endpoint on a given address").Hidden().BoolVar(&ccf.Gops)
	start.Flag("gops-addr",
		"Specify gops addr to listen on").Hidden().StringVar(&ccf.GopsAddr)
	start.Flag("diag-addr",
		"Start diangonstic endpoint on this address").Hidden().StringVar(&ccf.DiagnosticAddr)
	start.Flag("permit-user-env",
		"Enables reading of ~/.tsh/environment when creating a session").Hidden().BoolVar(&ccf.PermitUserEnvironment)
	start.Flag("insecure",
		"Insecure mode disables certificate validation [NOT FOR PRODUCTION]").Hidden().BoolVar(&ccf.InsecureMode)

	// define start's usage info (we use kingpin's "alias" field for this)
	start.Alias(usageNotes + usageExamples)

	// define a hidden 'scp' command (it implements server-side implementation of handling
	// 'scp' requests)
	scpc.Flag("t", "sink mode (data consumer)").Short('t').Default("false").BoolVar(&scpCommand.Sink)
	scpc.Flag("f", "source mode (data producer)").Short('f').Default("false").BoolVar(&scpCommand.Source)
	scpc.Flag("v", "verbose mode").Default("false").Short('v').BoolVar(&scpCommand.Verbose)
	scpc.Flag("r", "recursive mode").Default("false").Short('r').BoolVar(&scpCommand.Recursive)
	scpc.Flag("d", "directory mode").Short('d').Hidden().Bool()
	scpc.Flag("remote-addr", "address of the remote client").StringVar(&scpCommand.RemoteAddr)
	scpc.Flag("local-addr", "local address which accepted the request").StringVar(&scpCommand.LocalAddr)
	scpc.Arg("target", "").StringsVar(&scpCommand.Target)

	// parse CLI commands+flags:
	command, err := app.Parse(options.Args)
	if err != nil {
		utils.FatalError(err)
	}

	// create the default configuration:
	conf = service.MakeDefaultConfig()

	// execute the selected command unless we're running tests
	switch command {
	case start.FullCommand():
		// configuration merge: defaults -> file-based conf -> CLI conf
		if err = config.Configure(&ccf, conf); err != nil {
			utils.FatalError(err)
		}
		if !options.InitOnly {
			log.Debug(conf.DebugDumpToYAML())
		}
		if ccf.HTTPProfileEndpoint {
			log.Warningf("http profile endpoint is deprecated, use gops instead")
		}
		if ccf.Gops {
			log.Debugf("starting gops agent")
			err := agent.Listen(&agent.Options{Addr: ccf.GopsAddr})
			if err != nil {
				log.Warningf("failed to start gops agent %v", err)
			}
		}
		// collect and expose diagnostic endpoint
		if ccf.DiagnosticAddr != "" {
			mux := http.NewServeMux()
			mux.Handle("/metrics", prometheus.Handler())
			mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
				roundtrip.ReplyJSON(w, http.StatusOK, map[string]interface{}{"status": "ok"})
			})
			go func() {
				err := http.ListenAndServe(ccf.DiagnosticAddr, mux)
				if err != nil {
					log.Warningf("diagnostic endpoint exited %v", err)
				}
			}()
		}
		if !options.InitOnly {
			err = OnStart(conf)
		}
	case scpc.FullCommand():
		err = onSCP(&scpCommand)
	case status.FullCommand():
		err = onStatus()
	case dump.FullCommand():
		onConfigDump()
	case ver.FullCommand():
		utils.PrintVersion()
	}
	if err != nil {
		utils.FatalError(err)
	}
	log.Info("teleport: clean exit")
	return command, conf
}

// OnStart is the handler for "start" CLI command
func OnStart(config *service.Config) error {
	srv, err := service.NewTeleport(config)
	if err != nil {
		return trace.Wrap(err, "initializing teleport")
	}

	if err := srv.Start(); err != nil {
		return trace.Wrap(err, "starting teleport")
	}

	// create the pid file
	if config.PIDFile != "" {
		f, err := os.OpenFile(config.PIDFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0666)
		if err != nil {
			return trace.Wrap(err, "failed to create the PID file")
		}
		fmt.Fprintf(f, "%v", os.Getpid())
		defer f.Close()
	}

	return trace.Wrap(srv.Wait())
}

// onStatus is the handler for "status" CLI command
func onStatus() error {
	sshClient := os.Getenv("SSH_CLIENT")
	systemUser := os.Getenv("USER")
	teleportUser := os.Getenv(teleport.SSHTeleportUser)
	proxyHost := os.Getenv(teleport.SSHSessionWebproxyAddr)
	clusterName := os.Getenv(teleport.SSHTeleportClusterName)
	hostUUID := os.Getenv(teleport.SSHTeleportHostUUID)
	sid := os.Getenv(teleport.SSHSessionID)

	if sid == "" || proxyHost == "" {
		fmt.Println("You are not inside of a Teleport SSH session")
		return nil
	}

	fmt.Printf("User ID     : %s, logged in as %s from %s\n", teleportUser, systemUser, sshClient)
	fmt.Printf("Cluster Name: %s\n", clusterName)
	fmt.Printf("Host UUID   : %s\n", hostUUID)
	fmt.Printf("Session ID  : %s\n", sid)
	fmt.Printf("Session URL : https://%s/web/cluster/%v/node/%v/%v/%v\n", proxyHost, clusterName, hostUUID, systemUser, sid)

	return nil
}

// onConfigDump is the handler for "configure" CLI command
func onConfigDump() {
	sfc := config.MakeSampleFileConfig()
	fmt.Printf("%s\n%s\n", sampleConfComment, sfc.DebugDumpToYAML())
}

// onSCP implements handling of 'scp' requests on the server side. When the teleport SSH daemon
// receives an SSH "scp" request, it launches itself with 'scp' flag under the requested
// user's privileges
//
// This is the entry point of "teleport scp" call (the parent process is the teleport daemon)
func onSCP(cmd *scp.Command) (err error) {
	// when 'teleport scp' is executed, it cannot write logs to stderr (because
	// they're automatically replayed by the scp client)
	utils.SwitchLoggingtoSyslog()
	if len(cmd.Target) == 0 {
		return trace.BadParameter("teleport scp: missing an argument")
	}

	// get user's home dir (it serves as a default destination)
	cmd.User, err = user.Current()
	if err != nil {
		return trace.Wrap(err)
	}
	// see if the target is absolute. if not, use user's homedir to make
	// it absolute (and if the user doesn't have a homedir, use "/")
	target := cmd.Target[0]
	if !filepath.IsAbs(target) {
		if !utils.IsDir(cmd.User.HomeDir) {
			slash := string(filepath.Separator)
			cmd.Target[0] = slash + target
		} else {
			cmd.Target[0] = filepath.Join(cmd.User.HomeDir, target)
		}
	}
	if !cmd.Source && !cmd.Sink {
		return trace.Errorf("remote mode is not supported")
	}
	return trace.Wrap(cmd.Execute(&StdReadWriter{}))
}

type StdReadWriter struct {
}

func (rw *StdReadWriter) Read(b []byte) (int, error) {
	return os.Stdin.Read(b)
}

func (rw *StdReadWriter) Write(b []byte) (int, error) {
	return os.Stdout.Write(b)
}
