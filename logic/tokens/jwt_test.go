// Copyright (c) The Blocky Source,
// SPDX-License-Identifier: BUSL-1.1

package tokens

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"github.com/blockysource/authz/logic/keys"
	"github.com/blockysource/authz/pkg/rawjson"
	"github.com/blockysource/authz/types/algorithm"
	"strings"
	"testing"
	"time"
)

func TestJWTComposer_Sign(t *testing.T) {
	gen := keys.DefaultGenerator()

	now := time.Date(2023, 10, 4, 22, 39, 0, 0, time.UTC)
	keyID := "key_id"

	defaultClaims := InputClaims{
		JWTID:          "jwt_id",
		Issuer:         "issuer",
		Subject:        "subject",
		Audience:       []string{"audience"},
		ExpirationTime: now.Add(time.Hour),
		NotBefore:      now,
		IssuedAt:       now,
		Scope:          "scope",
		CustomClaims: rawjson.KeyValues{{
			Key:   "key",
			Value: json.RawMessage(`"value"`),
		}},
	}

	mustMarshalJSONB64 := func(v any) string {
		var buf bytes.Buffer
		be := base64.NewEncoder(base64.RawURLEncoding, &buf)
		if err := json.NewEncoder(be).Encode(v); err != nil {
			panic(err)
		}
		be.Close()
		return buf.String()
	}

	mustDecodeB64 := func(s string) string {
		dec, err := base64.RawURLEncoding.DecodeString(s)
		if err != nil {
			panic(err)
		}
		return string(dec)
	}

	type args struct {
		alg   algorithm.SigningAlgorithm
		input InputClaims
		keyID string
	}
	tests := []struct {
		name    string
		args    args
		testFn  func(t *testing.T, kID string, input InputClaims, got string)
		wantErr bool
	}{
		{
			name: "HS256",
			args: args{
				alg: algorithm.SigningAlgorithmHS256,
			},
			wantErr: false,
			testFn: func(t *testing.T, kID string, input InputClaims, got string) {
				// The third part is a signature.
			},
		},
		{
			name: "RSA512",
			args: args{
				alg: algorithm.SigningAlgorithmRS512,
			},
			wantErr: false,
		},
		{
			name: "ES256",
			args: args{
				alg: algorithm.SigningAlgorithmES256,
			},
		},
		{
			name: "PS256",
			args: args{
				alg: algorithm.SigningAlgorithmPS256,
			},
		},
		{
			name: "EdDSA",
			args: args{
				alg: algorithm.SigningAlgorithmEdDSA,
			},
		},
		{
			name: "None",
			args: args{
				alg: algorithm.SigningAlgorithmNone,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			j := JWTComposer{}

			coreID := tt.args.keyID
			if coreID == "" {
				coreID = keyID
			}

			input := tt.args.input
			if input.JWTID == "" {
				input = defaultClaims
			}

			var key *keys.SigningKey
			if tt.args.alg.IsNone() {
				key = keys.NewNoneSigningKey()
			} else {
				var err error
				key, err = gen.GenerateSigningKey(coreID, 0, tt.args.alg)
				if err != nil {
					t.Fatal(err)
				}
			}

			got, err := j.IssueAndSignToken(key, input)
			if (err != nil) != tt.wantErr {
				t.Errorf("Sign() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			h := JWTHeader{KeyID: key.KeyID, Algorithm: tt.args.alg.Rfc7518(), Type: "JWT"}
			wantHeader := mustMarshalJSONB64(h)

			parts := strings.Split(got, ".")
			if len(parts) < 2 {
				t.Fatalf("expected at least 2 parts, got %d", len(parts))
			}

			if parts[0] != wantHeader {
				t.Errorf("expected header \n%s\ngot: \n%s", mustDecodeB64(wantHeader), mustDecodeB64(parts[0]))
			}

			claims := Claims{
				StdClaims: StdClaims{
					JWTID:          input.JWTID,
					Issuer:         input.Issuer,
					Subject:        input.Subject,
					Audience:       input.Audience,
					Scope:          input.Scope,
					ExpirationTime: input.ExpirationTime.Unix(),
					NotBefore:      input.NotBefore.Unix(),
					IssuedAt:       input.IssuedAt.Unix(),
				},
				CustomClaims: input.CustomClaims,
			}

			wantClaims := mustMarshalJSONB64(claims)
			if parts[1] != wantClaims {
				t.Errorf("expected claims \n%s\ngot: \n%s", mustDecodeB64(wantClaims), mustDecodeB64(parts[1]))
			}
			if tt.testFn != nil {
				tt.testFn(t, key.KeyID, input, got)
			}

			t.Log(got)
		})
	}
}
