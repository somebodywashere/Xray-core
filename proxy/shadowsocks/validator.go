package shadowsocks

import (
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"hash/crc64"
	"strings"
	"sync"
	"unicode"

	"github.com/xtls/xray-core/common/dice"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
)

// Validator stores valid Shadowsocks users.
type Validator struct {
	sync.RWMutex
	users  []*protocol.MemoryUser
	emails map[string]struct{}
	keys   map[cipherKey]struct{}

	behaviorSeed  uint64
	behaviorFused bool
}

var ErrNotFound = errors.New("Not Found")

type cipherKey struct {
	method CipherType
	key    string
}

// Canonical member of each Unicode simple-fold class, as used by strings.EqualFold.
func foldedEmail(email string) string {
	return strings.Map(func(r rune) rune {
		for {
			next := unicode.SimpleFold(r)
			if next <= r {
				return next
			}
			r = next
		}
	}, email)
}

// Add a Shadowsocks user.
func (v *Validator) Add(u *protocol.MemoryUser) error {
	v.Lock()
	defer v.Unlock()

	account := u.Account.(*MemoryAccount)
	if len(v.users) != 0 {
		first := v.users[0]
		firstAccount := first.Account.(*MemoryAccount)
		if !firstAccount.Cipher.IsAEAD() || !account.Cipher.IsAEAD() {
			return errors.New("multi-user Shadowsocks requires AEAD")
		}
		// UDP uses a short-lived, single-user validator for subsequent packets.
		// Build the indexes only when this validator actually becomes multi-user.
		if v.keys == nil {
			v.emails = make(map[string]struct{})
			if first.Email != "" {
				v.emails[foldedEmail(first.Email)] = struct{}{}
			}
			v.keys = map[cipherKey]struct{}{{firstAccount.CipherType, string(firstAccount.Key)}: {}}
		}
	}
	if v.keys != nil {
		email := foldedEmail(u.Email)
		if _, exists := v.emails[email]; exists {
			return errors.New("duplicate user email: ", u.Email)
		}
		key := cipherKey{account.CipherType, string(account.Key)}
		if _, exists := v.keys[key]; exists {
			return errors.New("duplicate Shadowsocks credentials")
		}
		if email != "" {
			v.emails[email] = struct{}{}
		}
		v.keys[key] = struct{}{}
	}
	v.users = append(v.users, u)

	if !v.behaviorFused {
		hashkdf := hmac.New(sha256.New, []byte("SSBSKDF"))
		hashkdf.Write(account.Key)
		v.behaviorSeed = crc64.Update(v.behaviorSeed, crc64.MakeTable(crc64.ECMA), hashkdf.Sum(nil))
	}

	return nil
}

// Del a Shadowsocks user with a non-empty Email.
func (v *Validator) Del(email string) error {
	if email == "" {
		return errors.New("Email must not be empty.")
	}

	v.Lock()

	idx := -1
	for i, u := range v.users {
		if strings.EqualFold(u.Email, email) {
			idx = i
			break
		}
	}

	if idx == -1 {
		v.Unlock()
		return errors.New("User ", email, " not found.")
	}
	ulen := len(v.users)
	stop := v.users[idx].Sessions.Revoke()
	if v.keys != nil {
		u := v.users[idx]
		a := u.Account.(*MemoryAccount)
		delete(v.emails, foldedEmail(u.Email))
		delete(v.keys, cipherKey{a.CipherType, string(a.Key)})
	}

	v.users[idx] = v.users[ulen-1]
	v.users[ulen-1] = nil
	v.users = v.users[:ulen-1]
	v.Unlock()
	stop()
	return nil
}

// GetByEmail Get a Shadowsocks user with a non-empty Email.
func (v *Validator) GetByEmail(email string) *protocol.MemoryUser {
	if email == "" {
		return nil
	}

	v.Lock()
	defer v.Unlock()

	for _, u := range v.users {
		if strings.EqualFold(u.Email, email) {
			return u
		}
	}
	return nil
}

// GetAll get all users
func (v *Validator) GetAll() []*protocol.MemoryUser {
	v.Lock()
	defer v.Unlock()
	dst := make([]*protocol.MemoryUser, len(v.users))
	copy(dst, v.users)
	return dst
}

// GetCount get users count
func (v *Validator) GetCount() int64 {
	v.Lock()
	defer v.Unlock()
	return int64(len(v.users))
}

// Get a Shadowsocks user.
func (v *Validator) Get(bs []byte, command protocol.RequestCommand) (u *protocol.MemoryUser, aead cipher.AEAD, ret []byte, ivLen int32, err error) {
	v.RLock()
	defer v.RUnlock()

	for _, user := range v.users {
		if account := user.Account.(*MemoryAccount); account.Cipher.IsAEAD() {
			// AEAD payload decoding requires the payload to be over 32 bytes
			if len(bs) < 32 {
				continue
			}

			aeadCipher := account.Cipher.(*AEADCipher)
			ivLen = aeadCipher.IVSize()
			iv := bs[:ivLen]
			subkey := make([]byte, 32)
			subkey = subkey[:aeadCipher.KeyBytes]
			hkdfSHA1(account.Key, iv, subkey)
			aead = aeadCipher.AEADAuthCreator(subkey)

			var matchErr error
			switch command {
			case protocol.RequestCommandTCP:
				data := make([]byte, 4+aead.NonceSize())
				ret, matchErr = aead.Open(data[:0], data[4:], bs[ivLen:ivLen+18], nil)
			case protocol.RequestCommandUDP:
				data := make([]byte, 8192)
				ret, matchErr = aead.Open(data[:0], data[8192-aead.NonceSize():8192], bs[ivLen:], nil)
			}

			if matchErr == nil {
				u = user
				return
			}
		} else {
			u = user
			ivLen = user.Account.(*MemoryAccount).Cipher.IVSize()
			return
		}
	}

	return nil, nil, nil, 0, ErrNotFound
}

func (v *Validator) GetBehaviorSeed() uint64 {
	v.Lock()
	defer v.Unlock()

	v.behaviorFused = true
	if v.behaviorSeed == 0 {
		v.behaviorSeed = dice.RollUint64()
	}
	return v.behaviorSeed
}
