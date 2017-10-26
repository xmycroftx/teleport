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
	"sync"
	"time"

	"github.com/gravitational/teleport/lib/backend"
	"github.com/gravitational/trace"
	"github.com/gravitational/ttlmap"

	"github.com/jonboulle/clockwork"
	log "github.com/sirupsen/logrus"
)

// Backend implements backend.Backend interface using a in-memory backend.
type Backend struct {
	*log.Entry

	clock clockwork.Clock

	storeMu sync.Mutex
	store   *ttlmap.TTLMap
}

// New creates a new instance of a in-memory backend, it conforms to the
// backend.NewFunc interface.
func New() (backend.Backend, error) {
	ttlm, err := ttlmap.New(1000)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	bk := &Backend{
		clock: clockwork.NewRealClock(),
		store: ttlm,
		Entry: log.WithFields(log.Fields{
			trace.Component:       "backend:memory",
			trace.ComponentFields: log.Fields{},
		}),
	}
	return bk, nil
}

// GetKeys returns a list of keys for a given path
func (bk *Backend) GetKeys(bucket []string) ([]string, error) {
	return nil, nil
}

// CreateVal creates value with a given TTL and key in the bucket
// if the value already exists, it must return trace.AlreadyExistsError
func (bk *Backend) CreateVal(bucket []string, key string, val []byte, ttl time.Duration) error {
	return nil
}

// UpsertVal updates or inserts value with a given TTL into a bucket
// ForeverTTL for no TTL
func (bk *Backend) UpsertVal(bucket []string, key string, val []byte, ttl time.Duration) error {
	return nil
}

// GetVal return a value for a given key in the bucket
func (bk *Backend) GetVal(path []string, key string) ([]byte, error) {
	return nil, nil
}

// DeleteKey deletes a key in a bucket
func (bk *Backend) DeleteKey(bucket []string, key string) error {
	return nil
}

// DeleteBucket deletes the bucket by a given path
func (bk *Backend) DeleteBucket(path []string, bkt string) error {
	return nil
}

// AcquireLock grabs a lock that will be released automatically in TTL
func (bk *Backend) AcquireLock(token string, ttl time.Duration) error {
	return nil
}

// ReleaseLock forces lock release before TTL
func (bk *Backend) ReleaseLock(token string) error {
	return nil
}

// Close releases the resources taken up by this backend
func (bk *Backend) Close() error {
	return nil
}

// Clock returns clock used by this backend
func (bk *Backend) Clock() clockwork.Clock {
	return nil
}
