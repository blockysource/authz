// Copyright (c) The Blocky Source,
// SPDX-License-Identifier: BUSL-1.1

package clients

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"sync"
	"time"

	secrethash "github.com/blockysource/go-secret-hash"
)

// ClientsLogic is the composer of the client.
type ClientsLogic struct {
	identifier struct {
		outLength     int
		randBinLength int
		randEncLength int
		tsEncLength   int
		// This should be a crypto.Reader, but for testing purposes it is
		// taken as variable.
		rd io.Reader
	} `wire:"-"`

	secret struct {
		length    int
		binLength int
		rd        io.Reader
	} `wire:"-"`
	hasher *secrethash.Hasher
}

// Options are the options for the clients logic.
type Options struct {
	IdentifierLength int
	SecretLength     int
}

// DefaultOptions are the default options for the clients logic.
func DefaultOptions() Options {
	return Options{
		IdentifierLength: 32,
		SecretLength:     64,
	}
}

// NewClientsLogic creates a new instance of the clients logic.
func NewClientsLogic(hasher *secrethash.Hasher, opts Options) (*ClientsLogic, error) {
	c := &ClientsLogic{
		hasher: hasher,
	}
	c.identifier.outLength = opts.IdentifierLength
	if c.identifier.outLength == 0 {
		return nil, errors.New("identifier length is 0")
	}
	c.secret.length = opts.SecretLength
	if c.secret.length == 0 {
		return nil, errors.New("secret length is 0")
	}
	return c, nil
}

type bufRandReader struct {
	elemSize     int
	randPoolSize int
	rander       io.Reader
	poolMu       sync.Mutex
	poolPos      int    // protected with poolMu
	pool         []byte // protected with poolMu
}

func newBufRandReader(elemSize int) *bufRandReader {
	return &bufRandReader{
		elemSize:     elemSize,
		randPoolSize: elemSize * 16,
		rander:       rand.Reader,
		pool:         make([]byte, elemSize*16),
		poolPos:      elemSize * 16,
	}
}

func (b *bufRandReader) Read(p []byte) (n int, err error) {
	if len(p) == 0 {
		return
	}
	if len(p) != b.elemSize {
		return 0, errors.New("invalid length")
	}

	b.poolMu.Lock()
	if b.poolPos == b.randPoolSize {
		_, err = io.ReadFull(b.rander, b.pool)
		if err != nil {
			b.poolMu.Unlock()
			return
		}
		b.poolPos = 0
	}
	copy(p, b.pool[b.poolPos:(b.poolPos+b.elemSize)])
	b.poolPos += b.elemSize
	b.poolMu.Unlock()
	return b.elemSize, nil
}

func (c *ClientsLogic) initIdentifier() {
	tsEncodedLen := base64.RawStdEncoding.EncodedLen(8)
	c.identifier.tsEncLength = tsEncodedLen
	if c.identifier.outLength-tsEncodedLen-1 < 0 {
		// If the length is too small then we need to increase it, by adding the base of a
		// timestamp encoded length.
		// Here we set the random length to 8 bytes, which is the length of the timestamp.
		c.identifier.outLength = base64.RawURLEncoding.EncodedLen(8) + 1 + tsEncodedLen
		c.identifier.randBinLength = 8
	} else {
		c.identifier.randBinLength = base64.RawURLEncoding.DecodedLen(c.identifier.outLength - 1 - tsEncodedLen)
	}
	c.identifier.randEncLength = base64.RawURLEncoding.EncodedLen(c.identifier.randBinLength)
	c.identifier.rd = newBufRandReader(c.identifier.randBinLength)
}

func (c *ClientsLogic) initSecret() {
	if c.secret.length == 0 {
		c.secret.length = 64
	}
	c.secret.binLength = base64.RawURLEncoding.DecodedLen(c.secret.length)
	c.secret.rd = newBufRandReader(c.secret.binLength)
}

// GenerateIdentifier generates an identifier.
func (c *ClientsLogic) GenerateIdentifier() (string, error) {
	tmp := make([]byte, c.identifier.randBinLength)
	_, err := c.identifier.rd.Read(tmp)
	if err != nil {
		return "", err
	}

	out := make([]byte, c.identifier.outLength)
	base64.RawStdEncoding.Encode(out[:c.identifier.randEncLength], tmp)
	out[c.identifier.randEncLength] = '_'

	tm := time.Now().UnixNano()
	if len(tmp) < 8 {
		tmp = make([]byte, 8)
	} else {
		tmp = tmp[:8]
	}
	binary.BigEndian.PutUint64(tmp, uint64(tm))
	base64.RawStdEncoding.Encode(out[c.identifier.randEncLength+1:], tmp)

	return string(out), nil
}

// GenerateSecret generates a secret.
func (c *ClientsLogic) GenerateSecret() ([]byte, error) {
	tmp := make([]byte, c.secret.binLength)
	_, err := c.secret.rd.Read(tmp)
	if err != nil {
		return nil, err
	}

	out := make([]byte, c.secret.length)
	base64.RawURLEncoding.Encode(out, tmp)

	return out, nil
}

// // EncryptSecret encrypts the secret.
// func (c *ClientsLogic) EncryptSecret(ctx context.Context, secret []byte) ([]byte, error) {
// 	return c.secretsKeeper.Encrypt(ctx, secret)
// }
//
// // DecryptSecret decrypts the secret.
// func (c *ClientsLogic) DecryptSecret(ctx context.Context, secret []byte) ([]byte, error) {
// 	return c.secretsKeeper.Decrypt(ctx, secret)
// }

// HashSecret hashes the secret.
func (c *ClientsLogic) HashSecret(secret []byte) (secrethash.SecretHash, error) {
	return c.hasher.GenerateSecretHash(secret, nil)
}

// CompareSecretHash compares the secret hash with the secret.
func (c *ClientsLogic) CompareSecretHash(secretHash []byte, secret []byte) error {
	parsedSecretHash, err := c.hasher.Parse(secretHash, nil)
	if err != nil {
		return err
	}
	return parsedSecretHash.CompareSecret(secret)
}
