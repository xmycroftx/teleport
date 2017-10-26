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

package memory

import (
	"fmt"

	"github.com/gravitational/teleport/lib/utils"

	"gopkg.in/check.v1"
)

type BackendSuite struct {
}

var _ = check.Suite(&BackendSuite{})
var _ = fmt.Printf

func (s *BackendSuite) SetUpSuite(c *check.C) {
	utils.InitLoggerForTests()
}

func (s *BackendSuite) TearDownSuite(c *check.C) {
}

func (s *BackendSuite) SetUpTest(c *check.C) {
}

func (s *BackendSuite) TearDownTest(c *check.C) {
}

func (s *BackendSuite) TestFoo(c *check.C) {
}
