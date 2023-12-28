// Copyright (c) The Blocky Source,
// SPDX-License-Identifier: BUSL-1.1

package rawjson

import (
	"bytes"
	"fmt"
	"strconv"
	"sync"

	"encoding/json"
)

var (
	_readerPool = sync.Pool{}
	_bufPool    = sync.Pool{}
)

func getReader() *bytes.Reader {
	pv := _readerPool.Get()
	switch pv := pv.(type) {
	case *bytes.Reader:
		return pv
	default:
		return bytes.NewReader(nil)
	}
}

func putReader(r *bytes.Reader) {
	r.Reset(nil)
	_readerPool.Put(r)
}

func getBuffer() *bytes.Buffer {
	pv := _bufPool.Get()
	switch pv := pv.(type) {
	case *bytes.Buffer:
		return pv
	default:
		return bytes.NewBuffer(nil)
	}
}

func putBuffer(b *bytes.Buffer) {
	b.Reset()
	_bufPool.Put(b)
}

// KeyValue is a simple pair of key and value, where the key is simply a string and a value
// is a raw, unmodified JSON message.
type KeyValue struct {
	Key   string
	Value json.RawMessage
}

// DecodeString decodes the value as a string.
func (k KeyValue) DecodeString() (string, error) {
	var s string
	err := json.Unmarshal(k.Value, &s)
	return s, err
}

// DecodeInt64 decodes the value as an int64.
func (k KeyValue) DecodeInt64() (int64, error) {
	var i int64
	err := json.Unmarshal(k.Value, &i)
	return i, err
}

// DecodeBool decodes the value as a bool.
func (k KeyValue) DecodeBool() (bool, error) {
	var b bool
	err := json.Unmarshal(k.Value, &b)
	return b, err
}

// KeyValues is a slice of KeyValue
type KeyValues []KeyValue

// UnmarshalJSON implements json.Unmarshaler interface.
func (k *KeyValues) UnmarshalJSON(data []byte) error {
	// Get the reader from the pool.
	r := getReader()

	defer putReader(r)

	r.Reset(data)

	d := json.NewDecoder(r)
	t, err := d.Token()
	if err != nil {
		return err
	}

	if delim, ok := t.(json.Delim); !ok || delim != '{' {
		return fmt.Errorf("expect JSON object open with '{'")
	}

	for d.More() {
		var kv KeyValue
		t, err = d.Token()
		if err != nil {
			return err
		}

		switch tok := t.(type) {
		case json.Delim:
			if tok != '}' {
				return nil
			}
		case string:
			kv.Key = tok
		default:
			return fmt.Errorf("expecting JSON key should be always a string: %T: %v", t, t)
		}

		if err = d.Decode(&kv.Value); err != nil {
			return err
		}
		*k = append(*k, kv)
	}
	return nil
}

func (k KeyValues) MarshalJSON() ([]byte, error) {
	b := getBuffer()
	defer putBuffer(b)

	b.WriteByte('{')
	for i, kv := range k {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteByte('"')
		b.WriteString(kv.Key)
		b.WriteString(`":`)
		b.Write(kv.Value)
	}
	b.WriteByte('}')
	return b.Bytes(), nil
}

// SetOrReplaceInt64 sets or replaces the value of the key with the given int64 value.
func (k *KeyValues) SetOrReplaceInt64(key string, value int64, front bool) {
	for i, kv := range *k {
		if kv.Key == key {
			(*k)[i].Value = json.RawMessage(strconv.FormatInt(value, 10))
			return
		}
	}

	rawValue := json.RawMessage(strconv.FormatInt(value, 10))
	k.setKeyValue(key, rawValue, front)
}

// SetOrReplaceString sets or replaces the value of the key with the given string value.
func (k *KeyValues) SetOrReplaceString(key string, value string, front bool) error {
	rawValue, err := json.Marshal(value)
	if err != nil {
		return err
	}

	for i, kv := range *k {
		if kv.Key == key {
			(*k)[i].Value = rawValue
			return nil
		}
	}

	k.setKeyValue(key, rawValue, front)
	return nil
}

// ContainsKey returns true if the key exists in the key values.
func (k *KeyValues) ContainsKey(key string) bool {
	for _, kv := range *k {
		if kv.Key == key {
			return true
		}
	}
	return false
}

func (k *KeyValues) SetOrReplace(kv KeyValue) {
	for i, kv2 := range *k {
		if kv2.Key == kv.Key {
			(*k)[i].Value = kv.Value
			return
		}
	}
	*k = append(*k, kv)
}

// SetOrReplaceBool sets or replaces the value of the key with the given bool value.
func (k *KeyValues) SetOrReplaceBool(key string, value bool, front bool) {
	rawValue := json.RawMessage(strconv.FormatBool(value))
	for i, kv := range *k {
		if kv.Key == key {
			(*k)[i].Value = rawValue
			return
		}
	}

	k.setKeyValue(key, rawValue, front)
}

func (k *KeyValues) setKeyValue(key string, rawValue json.RawMessage, front bool) {
	kv := KeyValue{
		Key:   key,
		Value: rawValue,
	}
	if front {
		*k = append(*k, KeyValue{})
		copy((*k)[1:], *k)
		(*k)[0] = kv
	} else {
		*k = append(*k, kv)
	}
}
