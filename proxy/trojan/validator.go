package trojan

import (
	"strings"
	"sync"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
)

// Validator stores valid trojan users.
type Validator struct {
	mu    sync.Mutex
	email sync.Map
	users sync.Map
}

// Add a trojan user, Email must be empty or unique.
func (v *Validator) Add(u *protocol.MemoryUser) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	key := hexString(u.Account.(*MemoryAccount).Key)
	if _, exists := v.users.Load(key); exists {
		return errors.New("duplicate Trojan credential")
	}
	u = u.NewGeneration()
	if u.Email != "" {
		_, loaded := v.email.LoadOrStore(strings.ToLower(u.Email), u)
		if loaded {
			return errors.New("User ", u.Email, " already exists.")
		}
	}
	v.users.Store(key, u)
	return nil
}

// Del a trojan user with a non-empty Email.
func (v *Validator) Del(e string) error {
	if e == "" {
		return errors.New("Email must not be empty.")
	}
	le := strings.ToLower(e)
	v.mu.Lock()
	u, _ := v.email.LoadAndDelete(le)
	if u == nil {
		v.mu.Unlock()
		return errors.New("User ", e, " not found.")
	}
	user := u.(*protocol.MemoryUser)
	v.users.CompareAndDelete(hexString(user.Account.(*MemoryAccount).Key), user)
	stop := user.Sessions.Revoke()
	v.mu.Unlock()
	stop()
	return nil
}

// Get a trojan user with hashed key, nil if user doesn't exist.
func (v *Validator) Get(hash string) *protocol.MemoryUser {
	u, _ := v.users.Load(hash)
	if u != nil {
		return u.(*protocol.MemoryUser)
	}
	return nil
}

// Get a trojan user with hashed key, nil if user doesn't exist.
func (v *Validator) GetByEmail(email string) *protocol.MemoryUser {
	email = strings.ToLower(email)
	u, _ := v.email.Load(email)
	if u != nil {
		return u.(*protocol.MemoryUser)
	}
	return nil
}

// Get all users
func (v *Validator) GetAll() []*protocol.MemoryUser {
	u := make([]*protocol.MemoryUser, 0, 100)
	v.email.Range(func(key, value interface{}) bool {
		u = append(u, value.(*protocol.MemoryUser))
		return true
	})
	return u
}

// Get users count
func (v *Validator) GetCount() int64 {
	var c int64 = 0
	v.email.Range(func(key, value interface{}) bool {
		c++
		return true
	})
	return c
}
