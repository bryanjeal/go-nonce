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
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jmoiron/sqlx"
	uuid "github.com/satori/go.uuid"
)

const sqlCreateNonceTable string = `
PRAGMA foreign_keys = OFF;
-- Schema: nonce
ATTACH "nonce.sdb" AS "nonce";
BEGIN;
CREATE TABLE "nonce"."nonce"(
  "id" BINARY(16) NOT NULL,
  "user_id" BINARY(16) NOT NULL,
  "token" CHAR(88) NOT NULL,
  "action" TEXT,
  "salt" CHAR(24) NOT NULL,
  "is_used" BOOL NOT NULL DEFAULT 0,
  "is_valid" BOOL NOT NULL DEFAULT 1,
  "created_at" INTEGER NOT NULL,
  "expires_at" DATETIME NOT NULL
);
COMMIT;`

// tNonce holds the testing data
type NonceTest struct {
	Action    string
	UserID    uuid.UUID
	ExpiresIn time.Duration
}

var tNonce = NonceTest{
	Action:    "test-action",
	UserID:    uuid.NewV4(),
	ExpiresIn: time.Minute,
}

// Service that all tests will use
var nonce Service

type testService interface {
	Service
	TestTeardown()
}

// Wraper for NewService to make it work with the testService interface
func newServiceTest(db *sqlx.DB) testService {
	s := &nonceService{
		db: db,
	}
	go s.removeExpired()
	return s
}
func (s *nonceService) TestTeardown() {
	tx := s.db.MustBegin()
	tx.MustExec("DELETE FROM nonce;")
	tx.Commit()
}

// Wraper for NewInMemoryService to make it work with the testService interface
func newInMemoryServiceTest() testService {
	s := &nonceInMemoryService{
		store: &inMemStore{
			RWMutex:  &sync.RWMutex{},
			nonceMap: make(map[string]Nonce),
		},
	}

	go s.removeExpired()
	return s
}
func (s *nonceInMemoryService) TestTeardown() {
	s.store.Lock()
	s.store.nonceMap = make(map[string]Nonce)
	s.store.Unlock()
}

// TestServices contains all the tests to run
func TestServices(t *testing.T) {
	RemoveExpiredInterval = 50 * time.Millisecond

	dbFile := "nonce.sdb"
	// create database
	db := sqlx.MustConnect("sqlite3", dbFile)
	// create user table
	db.MustExec(sqlCreateNonceTable)

	services := []testService{
		newServiceTest(db),
		newInMemoryServiceTest(),
	}

	for _, nonce := range services {
		// Run tests
		t.Run("New", func(t *testing.T) {
			n, err := nonce.New(tNonce.Action, tNonce.UserID, tNonce.ExpiresIn)
			if err != nil {
				t.Fatalf("Expected to add nonce to DB. Instead got the error: %v", err)
			}
			if len(n.Token) != 88 {
				t.Fatalf("Expected Token to be 88 characters long. Instead length is: %d", len(n.Token))
			}
			if n.Action != tNonce.Action {
				t.Fatalf("Expected Action to be: %s. Instead got: %s", tNonce.Action, n.Action)
			}
			expiresAt := (time.Unix(n.CreatedAt, 0)).Add(tNonce.ExpiresIn)
			if n.ExpiresAt != expiresAt {
				t.Fatalf("Expected ExpiresAt to be: %s. Instead got: %s", expiresAt.String(), n.ExpiresAt.String())
			}
			if n.IsUsed != false {
				t.Fatalf("Expected IsUsed to be false. Instead got: %t", n.IsUsed)
			}
			if n.IsValid != true {
				t.Fatalf("Expected IsValid to be true. Instead got: %t", n.IsValid)
			}
			if n.UserID != tNonce.UserID {
				t.Fatalf("Expected UserID to be: %s. Instead got: %s", tNonce.UserID.String(), n.UserID.String())
			}

			// Clean Up
			nonce.TestTeardown()
		})

		t.Run("Check", func(t *testing.T) {
			n, err := nonce.New(tNonce.Action, tNonce.UserID, tNonce.ExpiresIn)
			if err != nil {
				t.Fatalf("Expected to add nonce to DB. Instead got the error: %v", err)
			}
			err = nonce.Check(n.Token, tNonce.Action, tNonce.UserID)
			if err != nil {
				t.Fatalf("Expected to nonce check to be valid. Instead got the error: %v", err)
			}
			err = nonce.Check("", tNonce.Action, tNonce.UserID)
			if err != ErrNoToken {
				t.Fatalf("Expected ErrNoToken. Instead got: %v", err)
			}
			err = nonce.Check("InvalidToken", tNonce.Action, tNonce.UserID)
			if err != ErrInvalidToken {
				t.Fatalf("Expected ErrInvalidToken. Instead got: %v", err)
			}
			err = nonce.Check(n.Token, "wrong action", tNonce.UserID)
			if err != ErrInvalidToken {
				t.Fatalf("Expected ErrInvalidToken. Instead got: %v", err)
			}
			err = nonce.Check(n.Token, tNonce.Action, uuid.NewV4())
			if err != ErrInvalidToken {
				t.Fatalf("Expected ErrInvalidToken. Instead got: %v", err)
			}

			// Clean Up
			nonce.TestTeardown()
		})

		t.Run("CheckExpired", func(t *testing.T) {
			n, err := nonce.New(tNonce.Action, tNonce.UserID, time.Duration(0))
			if err != nil {
				t.Fatalf("Expected to add nonce to DB. Instead got the error: %v", err)
			}
			err = nonce.Check(n.Token, tNonce.Action, tNonce.UserID)
			if err != ErrTokenExpired {
				t.Fatalf("Expected ErrTokenExpired. Instead got: %v", err)
			}

			// Clean Up
			nonce.TestTeardown()
		})

		t.Run("CheckInvalid", func(t *testing.T) {
			n, err := nonce.New(tNonce.Action, tNonce.UserID, tNonce.ExpiresIn)
			if err != nil {
				t.Fatalf("Expected to add nonce to DB. Instead got the error: %v", err)
			}
			_, err = nonce.New(tNonce.Action, tNonce.UserID, tNonce.ExpiresIn)
			if err != nil {
				t.Fatalf("Expected to add nonce to DB. Instead got the error: %v", err)
			}
			err = nonce.Check(n.Token, tNonce.Action, tNonce.UserID)
			if err != ErrInvalidToken {
				t.Fatalf("Expected ErrInvalidToken. Instead got: %v", err)
			}

			// Clean Up
			nonce.TestTeardown()
		})

		t.Run("CheckUsed", func(t *testing.T) {
			n, err := nonce.New(tNonce.Action, tNonce.UserID, tNonce.ExpiresIn)
			if err != nil {
				t.Fatalf("Expected to add nonce to DB. Instead got the error: %v", err)
			}
			_, err = nonce.Consume(n.Token)
			if err != nil {
				t.Fatalf("Expected token to be marked as used. Instead got the error: %v", err)
			}
			err = nonce.Check(n.Token, tNonce.Action, tNonce.UserID)
			if err != ErrTokenUsed {
				t.Fatalf("Expected ErrTokenUsed. Instead got: %v", err)
			}

			// Clean Up
			nonce.TestTeardown()
		})

		t.Run("Consume", func(t *testing.T) {
			n, err := nonce.New(tNonce.Action, tNonce.UserID, tNonce.ExpiresIn)
			if err != nil {
				t.Fatalf("Expected to add nonce to DB. Instead got the error: %v", err)
			}
			n2, err := nonce.Consume(n.Token)
			if err != nil {
				t.Fatalf("Expected token to be consumed. Instead got the error: %v", err)
			}

			if n2.IsUsed != true {
				t.Fatalf("Expected token to be marked as used.")
			}

			// Clean Up
			nonce.TestTeardown()
		})

		t.Run("ConsumeDuplicate", func(t *testing.T) {
			n, err := nonce.New(tNonce.Action, tNonce.UserID, tNonce.ExpiresIn)
			if err != nil {
				t.Fatalf("Expected to add nonce to DB. Instead got the error: %v", err)
			}
			_, err = nonce.Consume(n.Token)
			if err != nil {
				t.Fatalf("Expected token to be marked as used. Instead got the error: %v", err)
			}
			_, err = nonce.Consume(n.Token)
			if err != ErrTokenUsed {
				t.Fatalf("Expected ErrTokenUsed. Instead got: %v", err)
			}

			// Clean Up
			nonce.TestTeardown()
		})

		t.Run("CheckThenConsume", func(t *testing.T) {
			n, err := nonce.New(tNonce.Action, tNonce.UserID, tNonce.ExpiresIn)
			if err != nil {
				t.Fatalf("Expected to add nonce to DB. Instead got the error: %v", err)
			}
			n2, err := nonce.CheckThenConsume(n.Token, tNonce.Action, tNonce.UserID)
			if err != nil {
				t.Fatalf("Expected to nonce check to be valid. Instead got the error: %v", err)
			}

			if n2.IsUsed != true {
				t.Fatalf("Expected token to be marked as used.")
			}

			_, err = nonce.CheckThenConsume(n.Token, tNonce.Action, tNonce.UserID)
			if err != ErrTokenUsed {
				t.Fatalf("Expected ErrTokenUsed. Instead got: %v", err)
			}

			// Clean Up
			nonce.TestTeardown()
		})

		t.Run("Get", func(t *testing.T) {
			n, err := nonce.New(tNonce.Action, tNonce.UserID, tNonce.ExpiresIn)
			if err != nil {
				t.Fatalf("Expected to add nonce to DB. Instead got the error: %v", err)
			}

			getN, err := nonce.Get(tNonce.Action, tNonce.UserID)
			if err != nil {
				t.Fatalf("Expected get Nonce from DB. Instead got the error: %v", err)
			}

			if n.ID != getN.ID {
				t.Fatalf("Expected Nonce we just got to be the same as the one just added. N: %s. getN: %s", n.ID.String(), getN.ID.String())

			}

			n2, err := nonce.New(tNonce.Action, tNonce.UserID, tNonce.ExpiresIn)
			if err != nil {
				t.Fatalf("Expected to add nonce to DB. Instead got the error: %v", err)
			}

			getN2, err := nonce.Get(tNonce.Action, tNonce.UserID)
			if err != nil {
				t.Fatalf("Expected get Nonce from DB. Instead got the error: %v", err)
			}

			if n2.ID != getN2.ID {
				t.Fatalf("Expected Nonce we just got to be the same as the one just added. N2: %s. getN2: %s", n2.ID.String(), getN2.ID.String())
			}

			// Clean Up
			nonce.TestTeardown()
		})

		t.Run("RemoveExpired", func(t *testing.T) {
			n, err := nonce.New(tNonce.Action, tNonce.UserID, time.Millisecond)
			if err != nil {
				t.Fatalf("Expected to add nonce to DB. Instead got the error: %v", err)
			}
			time.Sleep(100 * time.Millisecond)
			err = nonce.Check(n.Token, tNonce.Action, tNonce.UserID)
			if err != ErrTokenNotFound {
				t.Fatalf("Expected ErrTokenNotFound. Instead got: %v", err)
			}

			// Clean Up
			nonce.TestTeardown()
		})
	}

	// Drop the Table(s) we created
	// Close the DB
	db.MustExec("drop table nonce;")
	db.Close()
	err := os.Remove(dbFile)
	if err != nil {
		t.Fatalf("Expected to remove dbFile: %s. Instead got the error: %v", dbFile, err)
	}
}
