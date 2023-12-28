// Copyright (c) The Blocky Source,
// SPDX-License-Identifier: BUSL-1.1

package rawjson

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestKeyValues_UnmarshalJSON(t *testing.T) {
	tc := []struct {
		name string
		data []byte
	}{
		{
			name: "simple",
			data: []byte(`{"key":"value"}`),
		},
		{
			name: "complex",
			data: []byte(`{"key":"value","key2":1,"key3":1.1,"key4":true,"key5":null,"key6":{"key":"value"}}`),
		},
	}

	for _, c := range tc {
		t.Run(c.name, func(t *testing.T) {
			var kv KeyValues
			err := kv.UnmarshalJSON(c.data)
			if err != nil {
				t.Fatal(err)
			}

			t.Logf("%+v\n", kv)
			md, err := kv.MarshalJSON()
			if err != nil {
				t.Fatal(err)
			}

			if bytes.Compare(md, c.data) != 0 {
				t.Fatalf("expected %s, got %s", string(c.data), string(md))
			}
		})
	}
}

func BenchmarkKeyValues(b *testing.B) {
	testJSON := []byte(`{"key":"value","key2":1,"key3":1.1,"key4":true,"key5":null,"key6":{"key":"value"}, "key7":{"some":{"empty": "object"}}}`)

	b.Run("KeyValues", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			var kv KeyValues
			err := json.Unmarshal(testJSON, &kv)
			if err != nil {
				b.Fatal("failed to unmarshal JSON object")
			}

			_, err = json.Marshal(kv)
			if err != nil {
				b.Fatal("failed to marshal KeyValues into JSON object")
			}
		}
	})

	b.Run("map[string]any", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			var kv map[string]any
			err := json.Unmarshal(testJSON, &kv)
			if err != nil {
				b.Fatal("failed to unmarshal JSON object")
			}

			_, err = json.Marshal(kv)
			if err != nil {
				b.Fatal("failed to marshal KeyValues into JSON object")
			}
		}
	})

}
