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

package srv

// Terminal defines an interface of functions for managing a (local or remote)
// PTY such as: executing commands within a PTY, resizing windows, and
// cleaning up.
type Terminal interface {
	// AddParty adds another participant to this terminal. We will keep the
	// Terminal open until all participants have left.
	AddParty(delta int)

	Run() error
	Wait() (*ExecResult, error)
	Kill() error

	PTY() io.ReadWriter
	TTY() *os.File

	Close() error

	GetWinSize() (*term.Winsize, error)
	SetWinSize(params rsession.TerminalParams) error
	GetTerminalParams() rsession.TerminalParams
	SetTermType(string)
}
