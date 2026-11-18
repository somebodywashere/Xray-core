package account

import (
	"errors"
	"sync"
	"sync/atomic"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
)

func (a *Account) AsAccount() (protocol.Account, error) {
	var VR net.Port
	if id, err := uuid.Parse(a.Auth); err == nil {
		VR = net.PortFromBytes(id[6:8])
	}
	return &MemoryAccount{
		Auth: a.Auth,
		VR:   VR,
	}, nil
}

type MemoryAccount struct {
	Auth string
	VR   net.Port
}

func (a *MemoryAccount) Equals(other protocol.Account) bool {
	if b, ok := other.(*MemoryAccount); ok {
		return a.Auth == b.Auth
	}
	return false
}

func (a *MemoryAccount) ToProto() proto.Message {
	return &Account{
		Auth: a.Auth,
	}
}

type Validator struct {
	users   sync.Map
	ids     sync.Map
	emails  map[string]*protocol.MemoryUser // guarded by mu; email matching is case-sensitive
	mu      sync.Mutex
	managed atomic.Bool
}

func NewValidator() *Validator {
	return &Validator{}
}

func (v *Validator) Add(user *protocol.MemoryUser) (err error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	auth := user.Account.(*MemoryAccount).Auth
	if v.Get(auth) != nil || v.emails[user.Email] != nil {
		return errors.New("duplicate Hysteria account")
	}
	user = user.NewGeneration()
	v.managed.Store(true)
	v.users.Store(auth, user)
	if user.Email != "" {
		if v.emails == nil {
			v.emails = make(map[string]*protocol.MemoryUser)
		}
		v.emails[user.Email] = user
	}
	if id, err := uuid.Parse(auth); err == nil {
		id[6] = 0
		id[7] = 0
		v.ids.Store(id, user)
	}
	return
}

func (v *Validator) DelByEmail(email string) (err error) {
	v.mu.Lock()
	user := v.emails[email]
	if user == nil {
		v.mu.Unlock()
		return errors.New("Hysteria user not found")
	}
	auth := user.Account.(*MemoryAccount).Auth
	delete(v.emails, email)
	v.users.Delete(auth)
	if id, err := uuid.Parse(auth); err == nil {
		id[6] = 0
		id[7] = 0
		v.ids.Delete(id)
	}
	stop := user.Sessions.Revoke()
	v.mu.Unlock()
	stop()
	return
}

func (v *Validator) Get(auth string) (user *protocol.MemoryUser) {
	if id, err := uuid.Parse(auth); err == nil {
		if user = v.GetByID(id); user != nil {
			VR := net.PortFromBytes(id[6:8])
			if user.Account.(*MemoryAccount).VR != VR {
				user = &protocol.MemoryUser{
					Email:    user.Email,
					Level:    user.Level,
					Sessions: user.Sessions,
					Account: &MemoryAccount{
						Auth: auth,
						VR:   VR,
					},
				}
			}
		}
		return
	}
	if value, ok := v.users.Load(auth); ok {
		user = value.(*protocol.MemoryUser)
	}
	return
}

func (v *Validator) GetByID(id uuid.UUID) (user *protocol.MemoryUser) {
	id[6] = 0
	id[7] = 0
	if value, ok := v.ids.Load(id); ok {
		user = value.(*protocol.MemoryUser)
	}
	return
}

func (v *Validator) GetByEmail(email string) (user *protocol.MemoryUser) {
	if email != "" {
		v.mu.Lock()
		defer v.mu.Unlock()
		return v.emails[email]
	}
	v.users.Range(func(key, value any) bool {
		if value.(*protocol.MemoryUser).Email == email {
			user = value.(*protocol.MemoryUser)
			return false
		}
		return true
	})
	return
}

func (v *Validator) GetAll() (users []*protocol.MemoryUser) {
	v.users.Range(func(key, value any) bool {
		users = append(users, value.(*protocol.MemoryUser))
		return true
	})
	return
}

func (v *Validator) GetCount() (count int64) {
	v.users.Range(func(key, value any) bool {
		count++
		return true
	})
	return
}

// Managed remains true after the last account is removed. Falling back to
// static transport authentication would reactivate a deleted credential.
func (v *Validator) Managed() bool {
	return v.managed.Load()
}

func (v *Validator) NotEmpty() (notEmpty bool) {
	v.users.Range(func(_, _ any) bool {
		notEmpty = true
		return false
	})
	return
}
