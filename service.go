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
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/bryanjeal/go-helpers"

	// handle mysql database
	_ "github.com/go-sql-driver/mysql"
	// handle sqlite3 database
	_ "github.com/mattn/go-sqlite3"

	"github.com/jmoiron/sqlx"
	uuid "github.com/satori/go.uuid"
)

// Errors
var (
	ErrNoToken       = errors.New("no token supplied")
	ErrInvalidToken  = errors.New("invalid token")
	ErrTokenUsed     = errors.New("duplicate submission")
	ErrTokenExpired  = errors.New("token expired")
	ErrTokenNotFound = errors.New("token not found")
)

// Service is the interface that provides auth methods.
type Service interface {
	// NewUserLocal registers a new user by a local account (email and password)
	New(action string, uid uuid.UUID, expiresIn time.Duration) (Nonce, error)

	// Check takes a Nonce token and checks to see if it is valid
	Check(token, action string, uid uuid.UUID) error

	// Consume takes a Nonce token and marks it as used
	Consume(token string) (Nonce, error)

	// CheckThenConsume checks to make sure Nonce token is valid and then marks it as used
	CheckThenConsume(token, action string, uid uuid.UUID) (Nonce, error)

	// Get takes a uid and action and returns the newest, valid nonce if it exists
	Get(action string, uid uuid.UUID) (Nonce, error)

	// Shutdown stops the removedExpired() function
	Shutdown()
}

// RemoveExpiredInterval can/should be set by applications using nonce.
// Default RemoveExpiredInterval is 24 Hours
var RemoveExpiredInterval = 24 * time.Hour

// Nonce Model holds token and token details
type Nonce struct {
	ID        uuid.UUID
	UserID    uuid.UUID `db:"user_id"`
	Token     string
	Action    string
	Salt      string
	IsUsed    bool      `db:"is_used"`
	IsValid   bool      `db:"is_valid"`
	CreatedAt int64     `db:"created_at"`
	ExpiresAt time.Time `db:"expires_at"`
}

type nonceService struct {
	db   *sqlx.DB
	quit chan struct{}
}

type nonceInMemoryService struct {
	store *inMemStore
	quit  chan struct{}
}
type inMemStore struct {
	*sync.RWMutex
	nonceMap map[string]Nonce
}

// NewService creates an Nonce Service that connects to provided DB information
// See service.sqlx.go for implementation details
func NewService(db *sqlx.DB) Service {
	s := &nonceService{
		db:   db,
		quit: make(chan struct{}),
	}
	go s.removeExpired()
	return s
}

// NewInMemoryService creates an Nonce Service that stores all nonces in memory
// See service.inmem.go for implementation details
func NewInMemoryService() Service {
	s := &nonceInMemoryService{
		store: &inMemStore{
			RWMutex:  &sync.RWMutex{},
			nonceMap: make(map[string]Nonce),
		},
		quit: make(chan struct{}),
	}
	go s.removeExpired()
	return s
}

// checkToken token does a basic check of the token based on length
func checkToken(token string) error {
	if len(strings.TrimSpace(token)) == 0 {
		return ErrNoToken
	} else if len(token) != 88 {
		return ErrInvalidToken
	}

	return nil
}

// All nonces have the same creation code. This stub generates the Nonce itself
// The services are responsible for storing the created Nonce
func newNonce(action string, uid uuid.UUID, expiresIn time.Duration) (Nonce, error) {
	// Generate salt
	rawSalt, err := helpers.Crypto.GenerateRandomKey(16)
	if err != nil {
		return Nonce{}, err
	}
	salt := base64.StdEncoding.EncodeToString(rawSalt)

	// get current time
	t := time.Now()

	// Generate new token
	rawToken := fmt.Sprintf("%s::%s::%d::%s", action, uid.String(), t.Unix(), salt)
	hasher := sha512.New()
	hasher.Write([]byte(rawToken))
	token := base64.URLEncoding.EncodeToString(hasher.Sum(nil))

	// We Truncate ExpiresAt because MySQL DateTime doesn't store past Seconds
	n := Nonce{
		UserID:    uid,
		Token:     token,
		Action:    action,
		Salt:      salt,
		IsUsed:    false,
		IsValid:   true,
		CreatedAt: t.Unix(),
		ExpiresAt: t.Add(expiresIn).Truncate(time.Second),
	}

	return n, nil
}

// checkNonce stub checks to make sure the nonce itself is valid
func checkNonce(n Nonce, action string, uid uuid.UUID) error {
	// make sure token is still valid
	if n.IsValid == false || n.Action != action || n.UserID != uid {
		return ErrInvalidToken
	}

	// make sure token hasn't been used
	if n.IsUsed == true {
		return ErrTokenUsed
	}

	// make sure token isn't expired
	t := time.Now()
	if n.ExpiresAt.After(t) == false {
		return ErrTokenExpired
	}
	return nil
}
