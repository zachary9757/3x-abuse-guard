package state

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"go.etcd.io/bbolt"
)

var (
	eventsBucket = []byte("events")
	bansBucket   = []byte("bans")
)

type Store struct {
	db *bbolt.DB
}

type EventRecord struct {
	ID        uint64    `json:"id"`
	Kind      string    `json:"kind"`
	Email     string    `json:"email"`
	SourceIP  string    `json:"source_ip"`
	Target    string    `json:"target"`
	Inbound   string    `json:"inbound"`
	Outbound  string    `json:"outbound"`
	CreatedAt time.Time `json:"created_at"`
	Raw       string    `json:"raw"`
}

type BanRecord struct {
	IP        string    `json:"ip"`
	Email     string    `json:"email"`
	Reason    string    `json:"reason"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

func Open(path string) (*Store, error) {
	if path == "" {
		return nil, errors.New("state path is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	db, err := bbolt.Open(path, 0o600, &bbolt.Options{Timeout: 2 * time.Second})
	if err != nil {
		return nil, err
	}
	s := &Store{db: db}
	if err := s.init(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *Store) init() error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		if _, err := tx.CreateBucketIfNotExists(eventsBucket); err != nil {
			return err
		}
		if _, err := tx.CreateBucketIfNotExists(bansBucket); err != nil {
			return err
		}
		return nil
	})
}

func (s *Store) RecordEvent(rec EventRecord) (EventRecord, error) {
	if rec.CreatedAt.IsZero() {
		rec.CreatedAt = time.Now()
	}
	err := s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(eventsBucket)
		id, err := b.NextSequence()
		if err != nil {
			return err
		}
		rec.ID = id
		data, err := json.Marshal(rec)
		if err != nil {
			return err
		}
		return b.Put(u64(id), data)
	})
	return rec, err
}

func (s *Store) CountEvents(email string, kind string, since time.Time) (int, error) {
	count := 0
	err := s.db.View(func(tx *bbolt.Tx) error {
		return tx.Bucket(eventsBucket).ForEach(func(_, v []byte) error {
			var rec EventRecord
			if err := json.Unmarshal(v, &rec); err != nil {
				return err
			}
			if rec.Email == email && rec.Kind == kind && !rec.CreatedAt.Before(since) {
				count++
			}
			return nil
		})
	})
	return count, err
}

func (s *Store) RecentEvents(limit int) ([]EventRecord, error) {
	if limit <= 0 {
		limit = 20
	}
	events := make([]EventRecord, 0, limit)
	err := s.db.View(func(tx *bbolt.Tx) error {
		c := tx.Bucket(eventsBucket).Cursor()
		for k, v := c.Last(); k != nil && len(events) < limit; k, v = c.Prev() {
			var rec EventRecord
			if err := json.Unmarshal(v, &rec); err != nil {
				return err
			}
			events = append(events, rec)
		}
		return nil
	})
	return events, err
}

func (s *Store) UpsertBan(rec BanRecord) error {
	if net.ParseIP(rec.IP) == nil {
		return fmt.Errorf("invalid ip: %s", rec.IP)
	}
	if rec.CreatedAt.IsZero() {
		rec.CreatedAt = time.Now()
	}
	data, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bbolt.Tx) error {
		return tx.Bucket(bansBucket).Put([]byte(rec.IP), data)
	})
}

func (s *Store) RemoveBan(ip string) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		return tx.Bucket(bansBucket).Delete([]byte(ip))
	})
}

func (s *Store) ListBans(now time.Time) ([]BanRecord, error) {
	if now.IsZero() {
		now = time.Now()
	}
	bans := []BanRecord{}
	err := s.db.View(func(tx *bbolt.Tx) error {
		return tx.Bucket(bansBucket).ForEach(func(_, v []byte) error {
			var rec BanRecord
			if err := json.Unmarshal(v, &rec); err != nil {
				return err
			}
			if rec.ExpiresAt.IsZero() || rec.ExpiresAt.After(now) {
				bans = append(bans, rec)
			}
			return nil
		})
	})
	return bans, err
}

func (s *Store) ExpiredBans(now time.Time) ([]BanRecord, error) {
	if now.IsZero() {
		now = time.Now()
	}
	bans := []BanRecord{}
	err := s.db.View(func(tx *bbolt.Tx) error {
		return tx.Bucket(bansBucket).ForEach(func(_, v []byte) error {
			var rec BanRecord
			if err := json.Unmarshal(v, &rec); err != nil {
				return err
			}
			if !rec.ExpiresAt.IsZero() && !rec.ExpiresAt.After(now) {
				bans = append(bans, rec)
			}
			return nil
		})
	})
	return bans, err
}

func u64(v uint64) []byte {
	out := make([]byte, 8)
	binary.BigEndian.PutUint64(out, v)
	return out
}
