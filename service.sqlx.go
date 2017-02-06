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
	"database/sql"
	"time"

	"github.com/golang/glog"
	// handle mysql database
	_ "github.com/go-sql-driver/mysql"
	// handle sqlite3 database
	_ "github.com/mattn/go-sqlite3"
	"github.com/satori/go.uuid"
)

func (s *nonceService) New(action string, uid uuid.UUID, expiresIn time.Duration) (Nonce, error) {
	n, err := newNonce(action, uid, expiresIn)
	if err != nil {
		return Nonce{}, err
	}

	// Save nonce to DB
	err = s.saveNonce(&n)
	if err != nil {
		return Nonce{}, err
	}

	// Invalidate existing tokens for same user & action
	sqlExec := `UPDATE nonce 
        SET is_valid = 0 
        WHERE is_valid = 1 AND user_id = :user_id AND action = :action AND id != :id`
	tx, err := s.db.Beginx()
	if err != nil {
		return Nonce{}, err
	}
	_, err = tx.NamedExec(sqlExec, &n)
	if err != nil {
		tx.Rollback()
		return Nonce{}, err
	}
	err = tx.Commit()
	if err != nil {
		return Nonce{}, err
	}

	// return new nonce
	return n, nil
}

func (s *nonceService) Check(token, action string, uid uuid.UUID) error {
	// make sure token was passed
	err := checkToken(token)
	if err != nil {
		return err
	}

	// get Nonce data from database
	n := Nonce{}
	err = s.db.Get(&n, "SELECT * FROM nonce WHERE token=$1", token)
	if err != nil && err != sql.ErrNoRows {
		return err
	} else if err == sql.ErrNoRows {
		return ErrTokenNotFound
	}

	err = checkNonce(n, action, uid)
	return err
}

func (s *nonceService) Consume(token string) (Nonce, error) {
	// make sure token was passed
	err := checkToken(token)
	if err != nil {
		return Nonce{}, err
	}

	n := Nonce{}
	err = s.db.Get(&n, "SELECT * FROM nonce WHERE token=$1", token)
	if err != nil && err != sql.ErrNoRows {
		return Nonce{}, err
	} else if err == sql.ErrNoRows {
		return Nonce{}, ErrTokenNotFound
	}

	// make sure token hasn't been used
	if n.IsUsed == true {
		return Nonce{}, ErrTokenUsed
	}

	// set token as used
	sqlExec := `UPDATE nonce SET is_used = 1 WHERE token=$1`
	tx, err := s.db.Beginx()
	if err != nil {
		return Nonce{}, err
	}
	_, err = tx.Exec(sqlExec, token)
	if err != nil {
		tx.Rollback()
		return Nonce{}, err
	}
	err = tx.Commit()
	if err != nil {
		return Nonce{}, err
	}

	n.IsUsed = true
	return n, nil
}

func (s *nonceService) CheckThenConsume(token, action string, uid uuid.UUID) (Nonce, error) {
	err := s.Check(token, action, uid)
	if err != nil {
		return Nonce{}, err
	}

	n, err := s.Consume(token)
	if err != nil {
		return Nonce{}, err
	}

	return n, nil
}

func (s *nonceService) Get(action string, uid uuid.UUID) (Nonce, error) {
	// get Nonce data from database
	n := Nonce{}
	err := s.db.Get(&n, "SELECT * FROM nonce WHERE action=$1 AND user_id=$2 AND is_valid=1 LIMIT 1", action, uid)
	if err != nil && err != sql.ErrNoRows {
		return Nonce{}, err
	} else if err == sql.ErrNoRows {
		return Nonce{}, ErrTokenNotFound
	}

	return n, nil
}

func (s *nonceService) Shutdown() {
	s.quit <- struct{}{}
}

// saveNonce saves or updates a nonce in the database
func (s *nonceService) saveNonce(n *Nonce) error {
	var sqlExec string

	// if id is nil then it is a new nonce
	if n.ID == uuid.Nil {
		// generate ID
		n.ID = uuid.NewV4()
		sqlExec = `INSERT INTO nonce 
		(id, user_id, token, action, salt, is_used, is_valid, created_at, expires_at)
		VALUES (:id, :user_id, :token, :action, :salt, :is_used, :is_valid, :created_at, :expires_at)`
	} else {
		sqlExec = `UPDATE nonce SET is_used=:is_used, is_valid=:is_valid WHERE id=:id`
	}

	tx, err := s.db.Beginx()
	if err != nil {
		return err
	}
	_, err = tx.NamedExec(sqlExec, &n)
	if err != nil {
		tx.Rollback()
		return err
	}
	err = tx.Commit()
	if err != nil {
		return err
	}

	return nil
}

// removeExpired removes expired nonces after a certain amount of time.
func (s *nonceService) removeExpired() {
	for {
		select {
		case <-s.quit:
			return
		default:
			sqlDelete := `DELETE FROM nonce WHERE expires_at < $1`

			t := time.Now()
			tx, err := s.db.Beginx()
			if err != nil {
				glog.Errorln("Error removing Expired Nonces.", err)
			}
			_, err = tx.Exec(sqlDelete, t)
			if err != nil {
				tx.Rollback()
				glog.Errorln("Error removing Expired Nonces.", err)
			}
			err = tx.Commit()
			if err != nil {
				glog.Errorln("Error removing Expired Nonces.", err)
			}

			//delay until the next interval
			time.Sleep(RemoveExpiredInterval)
		}
	}
}
