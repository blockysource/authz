// Copyright (c) The Blocky Source,
// SPDX-License-Identifier: BUSL-1.1

package tokens

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/blockysource/authz/logic/keys"
	"github.com/blockysource/authz/pkg/rawjson"
	"time"
)

// JwtTokenIssueSigner is a JWT sign issuer.
type JwtTokenIssueSigner interface {
	// IssueAndSignToken issues a new JWT token and signs it with the given key.
	// If the key is nil or the algorithm is none, then the token is not signed.
	IssueAndSignToken(key *keys.SigningKey, input InputClaims) (string, error)
}

// JWTComposer is a  JWT composer.
// NOTE: This struct may extend a standard token implementation, by providing specific option fields inside of the struct.
type JWTComposer struct {
}

// StdClaims is a JWT claims structure.
type StdClaims struct {
	// Issuer is the issuer of the token.
	Issuer string `json:"iss"`

	// Subject is the subject of the token.
	Subject string `json:"sub"`

	// Audience is the audience of the token.
	Audience Audience `json:"aud"`

	// ExpirationTime is the expiration time of the token.
	ExpirationTime int64 `json:"exp"`

	// NotBefore is the time before which the token must not be accepted for processing.
	NotBefore int64 `json:"nbf"`

	// IssuedAt is the time at which the token was issued.
	IssuedAt int64 `json:"iat"`

	// JWTID is the JWT ID.
	JWTID string `json:"jti,omitempty"`

	// Scope is a comma-separated list of authorization scopes, this token is valid for.
	Scope string `json:"scope,omitempty"`
}

// Claims is a structure that contains both the standard and custom claims.
type Claims struct {
	StdClaims
	CustomClaims rawjson.KeyValues
}

// MarshalJSON marshals the claims to JSON.
func (c Claims) MarshalJSON() ([]byte, error) {
	if len(c.CustomClaims) == 0 {
		return json.Marshal(c.StdClaims)
	}
	var buf bytes.Buffer
	je := json.NewEncoder(&buf)
	if err := je.Encode(c.StdClaims); err != nil {
		return nil, err
	}
	buf.Truncate(buf.Len() - 2)
	for _, kv := range c.CustomClaims {
		if kv.Key == "" || len(kv.Value) == 0 {
			return nil, errors.New("invalid claim key or value")
		}
		buf.WriteByte(',')
		buf.WriteByte('"')
		buf.WriteString(kv.Key)
		buf.WriteString(`":`)
		buf.Write(kv.Value)
	}
	buf.WriteByte('}')
	return buf.Bytes(), nil
}

// UnmarshalJSON unmarshals the claims from JSON.
func (c *Claims) UnmarshalJSON(data []byte) error {
	claims := rawjson.KeyValues{}
	if err := claims.UnmarshalJSON(data); err != nil {
		return err
	}

	for _, kv := range claims {
		switch kv.Key {
		case "iss":
			if err := json.Unmarshal(kv.Value, &c.Issuer); err != nil {
				return err
			}
		case "sub":
			if err := json.Unmarshal(kv.Value, &c.Subject); err != nil {
				return err
			}
		case "aud":
			if err := json.Unmarshal(kv.Value, &c.Audience); err != nil {
				return err
			}
		case "exp":
			if err := json.Unmarshal(kv.Value, &c.ExpirationTime); err != nil {
				return err
			}
		case "nbf":
			if err := json.Unmarshal(kv.Value, &c.NotBefore); err != nil {
				return err
			}
		case "iat":
			if err := json.Unmarshal(kv.Value, &c.IssuedAt); err != nil {
				return err
			}
		case "jti":
			if err := json.Unmarshal(kv.Value, &c.JWTID); err != nil {
				return err
			}
		default:
			c.CustomClaims = append(c.CustomClaims, kv)
		}
	}
	return nil
}

// Audience is a JWT audience.
type Audience []string

// MarshalJSON marshals the audience to JSON.
func (a Audience) MarshalJSON() ([]byte, error) {
	if len(a) == 1 {
		return []byte(fmt.Sprintf("%q", a[0])), nil
	}
	return json.Marshal([]string(a))
}

// UnmarshalJSON unmarshals the audience from JSON.
func (a *Audience) UnmarshalJSON(data []byte) error {
	d := json.NewDecoder(bytes.NewReader(data))
	if !d.More() {
		return nil
	}

	dt, err := d.Token()
	if err != nil {
		return err
	}

	switch v := dt.(type) {
	case json.Delim:
		if v != '[' {
			return errors.New("expecting JSON array or string")
		}
	case string:
		*a = Audience{v}
		return nil
	}

	for d.More() {
		dt, err = d.Token()
		if err != nil {
			return err
		}
		switch t := dt.(type) {
		case json.Delim:
			switch t {
			case ']':
				return nil
			case ',':
				continue
			default:
				return errors.New("expecting JSON array of strings or a string")
			}
		case string:
			*a = append(*a, t)
		default:
			return errors.New("expecting JSON array of strings or a string")
		}
	}
	return nil
}

// JWTHeader is a JWT header structure.
type JWTHeader struct {
	// Type is the token type.
	Type string `json:"typ"`

	// Algorithm is the signing algorithm.
	Algorithm string `json:"alg"`

	// KeyID is the key identifier.
	KeyID string `json:"kid,omitempty"`
}

// InputClaims is a JWT input claims structure.
type InputClaims struct {
	// Issuer is the issuer of the token.
	Issuer string

	// Subject is the subject of the token.
	Subject string

	// Audience is the audience of the token.
	Audience []string

	// ExpirationTime is the expiration time of the token.
	ExpirationTime time.Time

	// NotBefore is the time before which the token must not be accepted for processing.
	NotBefore time.Time

	// IssuedAt is the time at which the token was issued.
	IssuedAt time.Time

	// JWTID is the JWT ID.
	JWTID string

	// Scope is a comma-separated list of authorization scopes, this token is valid for.
	Scope string

	// CustomHeaders is a map of custom headers.
	CustomHeaders rawjson.KeyValues

	// CustomClaims is a map of custom claims.
	CustomClaims rawjson.KeyValues
}

// IssueAndSignToken signs the JWT with the given key.
func (j *JWTComposer) IssueAndSignToken(key *keys.SigningKey, input InputClaims) (string, error) {
	// Make a JWT token header.
	header := rawjson.KeyValues{}

	// Add Type header.
	header = append(header,
		rawjson.KeyValue{
			Key:   "typ",
			Value: json.RawMessage(`"JWT"`),
		},
		rawjson.KeyValue{
			Key:   "alg",
			Value: key.Algorithm.RawJSONRfc7518(),
		},
	)

	if key != nil && key.KeyID != "" {
		header = append(header,
			rawjson.KeyValue{
				Key:   "kid",
				Value: json.RawMessage(fmt.Sprintf(`"%s"`, key.KeyID)),
			},
		)
	}

	for _, kv := range input.CustomHeaders {
		if kv.Key == "typ" || kv.Key == "alg" || kv.Key == "kid" {
			continue
		}
		if kv.Key == "" || len(kv.Value) == 0 {
			return "", fmt.Errorf("invalid header key or value: %s", kv.Key)
		}
		header = append(header, kv)
	}

	var buf bytes.Buffer

	// Encode the header.
	be := base64.NewEncoder(base64.RawURLEncoding, &buf)
	je := json.NewEncoder(be)
	if err := je.Encode(header); err != nil {
		return "", err
	}
	if err := be.Close(); err != nil {
		return "", err
	}

	// Write the separator.
	buf.WriteByte('.')

	claims := rawjson.KeyValues{}
	// Add Issuer.
	if input.Issuer != "" {
		if err := claims.SetOrReplaceString("iss", input.Issuer, true); err != nil {
			return "", err
		}
	}
	// Add Subject.
	if input.Subject != "" {
		if err := claims.SetOrReplaceString("sub", input.Subject, false); err != nil {
			return "", err
		}
	}
	// Add Audience.
	switch len(input.Audience) {
	case 0:
	case 1:
		if err := claims.SetOrReplaceString("aud", input.Audience[0], false); err != nil {
			return "", err
		}
	default:
		kv := rawjson.KeyValue{
			Key: "aud",
		}
		var err error
		kv.Value, err = json.Marshal(input.Audience)
		if err != nil {
			return "", err
		}
		claims = append(claims, kv)
	}
	if !input.ExpirationTime.IsZero() {
		claims.SetOrReplaceInt64("exp", input.ExpirationTime.Unix(), false)
	}
	if !input.NotBefore.IsZero() {
		claims.SetOrReplaceInt64("nbf", input.NotBefore.Unix(), false)
	}
	if !input.IssuedAt.IsZero() {
		claims.SetOrReplaceInt64("iat", input.IssuedAt.Unix(), false)
	}
	if input.JWTID != "" {
		if err := claims.SetOrReplaceString("jti", input.JWTID, false); err != nil {
			return "", err
		}
	}

	if input.Scope != "" {
		if err := claims.SetOrReplaceString("scope", input.Scope, false); err != nil {
			return "", err
		}
	}

	// Check if there are any custom claims that do not collide with the reserved claims.
	for _, kv := range input.CustomClaims {
		switch kv.Key {
		case "iss", "sub", "aud", "exp", "nbf", "iat", "jti", "scope":
			continue
		}
		claims = append(claims, kv)
	}

	// Encode the claims.
	be = base64.NewEncoder(base64.RawURLEncoding, &buf)
	je = json.NewEncoder(be)
	if err := je.Encode(claims); err != nil {
		return "", err
	}

	if err := be.Close(); err != nil {
		return "", err
	}

	// IF the algorithm is none, then return the token.
	if key == nil || key.Algorithm.IsNone() {
		return buf.String(), nil
	}

	// Sign the token.
	signature, err := key.SignData(buf.Bytes())
	if err != nil {
		return "", err
	}

	// Write the separator.
	buf.WriteByte('.')

	_, err = base64.NewEncoder(base64.RawURLEncoding, &buf).Write(signature)
	if err != nil {
		return "", err
	}

	return buf.String(), nil
}
