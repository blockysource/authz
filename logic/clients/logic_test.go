// Copyright (c) The Blocky Source,
// SPDX-License-Identifier: BUSL-1.1

package clients

import (
	"crypto/rand"
	"testing"
)

func TestClientsLogic_GenerateIdentifier(t *testing.T) {
	c := ClientsLogic{}
	c.identifier.outLength = 40
	c.initIdentifier()
	c.identifier.rd = rand.Reader
	identifier, err := c.GenerateIdentifier()
	if err != nil {
		t.Fatal(err)
	}

	if len(identifier) != 40 {
		t.Errorf("identifier length is not 40: %d", len(identifier))
	}

	t.Logf("identifier: %s", identifier)
}

func TestClientsLogic_GenerateSecret(t *testing.T) {
	c := ClientsLogic{}
	c.initSecret()

	secret, err := c.GenerateSecret()
	if err != nil {
		t.Fatal(err)
	}

	if len(secret) == 0 {
		t.Error("secret is empty")
	}
}

func BenchmarkClientsLogic_GenerateIdentifier(b *testing.B) {
	b.Run("Buffered", func(b *testing.B) {
		c := ClientsLogic{}
		c.identifier.outLength = 40
		c.initIdentifier()

		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := c.GenerateIdentifier()
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("Unbuffered", func(b *testing.B) {
		c := ClientsLogic{}
		c.identifier.outLength = 40
		c.initIdentifier()
		c.identifier.rd = rand.Reader

		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := c.GenerateIdentifier()
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}


func BenchmarkClientsLogic_GenerateSecret(b *testing.B) {
	b.Run("Buffered", func(b *testing.B) {
		c := ClientsLogic{}
		c.initSecret()

		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := c.GenerateSecret()
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("Unbuffered", func(b *testing.B) {
		c := ClientsLogic{}
		c.initSecret()
		c.secret.rd = rand.Reader

		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := c.GenerateSecret()
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}