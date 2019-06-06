// Copyright 2018 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package boot

import (
	"reflect"
	"strings"
	"testing"
)

// TestParsePasswd tests the parsePasswd function's passwd file parsing.
func TestParsePasswd(t *testing.T) {
	tests := map[string]struct {
		passwd   string
		expected []user
	}{
		"empty": {
			passwd:   "",
			expected: []user{},
		},
		"whitespace": {
			passwd:   "       ",
			expected: []user{},
		},
		"full": {
			passwd: "adin::1000:1111::/home/adin:/bin/sh",
			expected: []user{
				{
					Name:  "adin",
					UID:   1000,
					GID:   1111,
					Home:  "/home/adin",
					Shell: "/bin/sh",
				},
			},
		},
		"multiple": {
			passwd: "adin::1000:1111::/home/adin:/bin/sh\nian::1001:1111::/home/ian:/bin/sh",
			expected: []user{
				{
					Name:  "adin",
					UID:   1000,
					GID:   1111,
					Home:  "/home/adin",
					Shell: "/bin/sh",
				},
				{
					Name:  "ian",
					UID:   1001,
					GID:   1111,
					Home:  "/home/ian",
					Shell: "/bin/sh",
				},
			},
		},
		"empty_lines": {
			passwd: "adin::1000:1111::/home/adin:/bin/sh\n\n\nian::1001:1111::/home/ian:/bin/sh",
			expected: []user{
				{
					Name:  "adin",
					UID:   1000,
					GID:   1111,
					Home:  "/home/adin",
					Shell: "/bin/sh",
				},
				{
					Name:  "ian",
					UID:   1001,
					GID:   1111,
					Home:  "/home/ian",
					Shell: "/bin/sh",
				},
			},
		},
		"partial": {
			passwd: "adin::1000:1111:",
			expected: []user{
				{
					Name: "adin",
					UID:  1000,
					GID:  1111,
				},
			},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := parsePasswd(strings.NewReader(tc.passwd))
			if err != nil {
				t.Fatalf("error parsing passwd: %v", err)
			}
			if !reflect.DeepEqual(tc.expected, got) {
				t.Fatalf("expected %v, got: %v", tc.expected, got)
			}
		})
	}
}
