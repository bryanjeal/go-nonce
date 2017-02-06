// Copyright 2016 Bryan Jeal <bryan@jeal.ca>

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

// 	http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package nonce

import (
	"time"

	"github.com/satori/go.uuid"
)

func (s *nonceInMemoryService) New(action string, uid uuid.UUID, expiresIn time.Duration) (Nonce, error) {
	n, err := newNonce(action, uid, expiresIn)
	if err != nil {
		return Nonce{}, err
	}

	// Save nonce
	n = s.saveNonce(n)

	// Invalidate existing tokens for same user & action
	s.store.Lock()
	for k, v := range s.store.nonceMap {
		if v.IsValid && v.UserID == n.UserID && v.Action == n.Action && v.ID != n.ID {
			v.IsValid = false
			s.store.nonceMap[k] = v
		}
	}
	s.store.Unlock()

	// return new nonce
	return n, nil
}

func (s *nonceInMemoryService) Check(token, action string, uid uuid.UUID) error {
	// make sure token was passed
	err := checkToken(token)
	if err != nil {
		return err
	}

	// get Nonce data from store
	n, err := s.getNonce(token)
	if err != nil {
		return err
	}

	err = checkNonce(n, action, uid)
	return err
}

func (s *nonceInMemoryService) Consume(token string) (Nonce, error) {
	// make sure token was passed
	err := checkToken(token)
	if err != nil {
		return Nonce{}, err
	}

	// get Nonce data from store
	n, err := s.getNonce(token)
	if err != nil {
		return Nonce{}, err
	}

	// make sure token hasn't been used
	if n.IsUsed == true {
		return Nonce{}, ErrTokenUsed
	}

	// set token as used
	n.IsUsed = true
	n = s.saveNonce(n)

	return n, nil
}

func (s *nonceInMemoryService) CheckThenConsume(token, action string, uid uuid.UUID) (Nonce, error) {
	err := s.Check(token, action, uid)
	if err != nil {
		return Nonce{}, err
	}

	n, err := s.Consume(token)
	return n, err
}

func (s *nonceInMemoryService) Get(action string, uid uuid.UUID) (Nonce, error) {
	var nonces []Nonce
	nonces = make([]Nonce, 1, 1)

	s.store.RLock()
	for _, n := range s.store.nonceMap {
		if n.Action == action && n.UserID == uid {
			nonces = append(nonces, n)
		}
	}
	s.store.RUnlock()

	if len(nonces) == 0 {
		return Nonce{}, ErrTokenNotFound
	} else if len(nonces) == 1 {
		return nonces[0], nil
	}

	newestN := nonces[0]
	for _, n := range nonces {
		if newestN.CreatedAt < n.CreatedAt && n.IsValid {
			newestN = n
		}
	}

	if newestN.IsValid == false {
		return Nonce{}, ErrTokenNotFound
	}

	return newestN, nil
}

func (s *nonceInMemoryService) Shutdown() {
	s.quit <- struct{}{}
}

// getNonce gets a Nonce from the store
func (s *nonceInMemoryService) getNonce(token string) (Nonce, error) {
	s.store.RLock()
	n, ok := s.store.nonceMap[token]
	s.store.RUnlock()
	if !ok {
		return Nonce{}, ErrTokenNotFound
	}

	return n, nil
}

// saveNonce saves or updates a Nonce
func (s *nonceInMemoryService) saveNonce(n Nonce) Nonce {
	// if id is nil then it is a new nonce
	if n.ID == uuid.Nil {
		// generate ID
		n.ID = uuid.NewV4()
	}

	s.store.Lock()
	s.store.nonceMap[n.Token] = n
	s.store.Unlock()

	return n
}

// removeExpired removes expired nonces after a certain amount of time.
func (s *nonceInMemoryService) removeExpired() {
	for {
		select {
		case <-s.quit:
			return
		default:
			t := time.Now()
			s.store.Lock()
			for k, v := range s.store.nonceMap {
				if v.ExpiresAt.Before(t) {
					delete(s.store.nonceMap, k)
				}

			}
			s.store.Unlock()

			//delay until the next interval
			time.Sleep(RemoveExpiredInterval)
		}

	}
}
