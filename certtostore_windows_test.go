// Copyright 2022 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package certtostore

import (
	"errors"
	"testing"
)

func TestGetPropertyStr(t *testing.T) {
	err1 := errors.New("test error")
	tests := []struct {
		desc    string
		out     []byte
		err     error
		want    string
		wantErr error
	}{
		{"with replacements",
			[]byte{104, 0, 101, 108, 0, 108, 111},
			nil,
			"hello",
			nil,
		},
		{"without replacements",
			[]byte{104, 101, 108, 108, 111},
			nil,
			"hello",
			nil,
		},
		{"error",
			[]byte{104, 0, 101, 108, 0, 108, 111},
			err1,
			"",
			err1,
		},
	}
	for _, tt := range tests {
		fnGetProperty = func(kh uintptr, property *uint16) ([]byte, error) {
			return tt.out, tt.err
		}
		out, err := getPropertyStr(0, nil)
		if out != tt.want {
			t.Errorf("%s produced unexpected result: got %s, want %s", tt.desc, out, tt.want)
		}
		if !errors.Is(err, tt.wantErr) {
			t.Errorf("%s produced unexpected error: got %v, want %v", tt.desc, err, tt.wantErr)
		}
	}
}
