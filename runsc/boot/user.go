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
	"bufio"
	"io"
	"strconv"
	"strings"

	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
	"gvisor.googlesource.com/gvisor/pkg/syserror"
)

// user represents a user record in passwd file.
type user struct {
	Name     string
	Password string
	UID      uint32
	GID      uint32
	Gecos    string
	Home     string
	Shell    string
}

type fileReader struct {
	// Ctx is the context for the file reader.
	Ctx context.Context

	// File is the file to read from.
	File *fs.File
}

// Read implements io.Reader.Read.
func (r *fileReader) Read(buf []byte) (int, error) {
	if r.Ctx.Interrupted() {
		return 0, syserror.ErrInterrupted
	}
	n, err := r.File.Readv(r.Ctx, usermem.BytesIOSequence(buf))
	return int(n), err
}

// getExecUser returns user information for the executing user read from
// /etc/passwd as read from the container filesystem.
func getExecUser(ctx context.Context, rootMns *fs.MountNamespace, uid uint32) (user, error) {
	// The default user to return if no user matching the user if found in the
	// /etc/passwd found in the image.
	execUser := user{
		Name: "root",
		UID:  0,
		GID:  0,
		Home: "/",
	}

	// Open the /etc/passwd file from the dirent via the root mount namespace
	maxTraversals := uint(0)
	mnsRoot := rootMns.Root()
	dirent, err := rootMns.FindInode(ctx, mnsRoot, nil, "/etc/passwd", &maxTraversals)
	if err != nil {
		// NOTE: Ignore errors opening the passwd file. If the passwd file
		// doesn't exist we will return the default user.
		return execUser, nil
	}

	f, err := dirent.Inode.GetFile(ctx, dirent, fs.FileFlags{Read: true, Directory: false})
	if err != nil {
		return execUser, err
	}

	r := &fileReader{
		Ctx:  ctx,
		File: f,
	}

	users, err := parsePasswd(r)
	if err != nil {
		return execUser, err
	}

	// Find the right user
	for _, u := range users {
		if u.UID == uid {
			execUser = u
		}
	}

	return execUser, nil
}

// parsePasswd parses a passwd file and returns the user records contained
// therein. Empty and whitespace only lines are ignored.
func parsePasswd(passwd io.Reader) ([]user, error) {
	s := bufio.NewScanner(passwd)
	users := []user{}

	for s.Scan() {
		if err := s.Err(); err != nil {
			return nil, err
		}

		line := strings.TrimSpace(s.Text())
		if line == "" {
			continue
		}

		users = append(users, parsePasswdLine(line))
	}

	return users, nil
}

// parsePasswdLine parses a line in a passwd file. The line should contain a
// valid user entry. This implementation is loose and will return users for
// lines without all fields, including all fields present. UIDs, GIDs not
// formatted as numbers will result in a user where there are set to zero.
//
// Per 'man 5 passwd'
// /etc/passwd contains one line for each user account, with seven
// fields delimited by colons (“:”). These fields are:
//
// - login name
// - optional encrypted password
// - numerical user ID
// - numerical group ID
// - user name or comment field
// - user home directory
// - optional user command interpreter
func parsePasswdLine(line string) user {
	parts := strings.Split(strings.TrimSpace(line), ":")

	// Pull out part of passwd entry. Ignore errors in passwd entry as some
	// passwd files could be poorly written.
	u := user{}
	for i, p := range parts {
		switch i {
		case 0:
			u.Name = p
		case 1:
			u.Password = p
		case 2:
			uid, _ := strconv.ParseUint(p, 10, 32)
			u.UID = uint32(uid)
		case 3:
			gid, _ := strconv.ParseUint(p, 10, 32)
			u.GID = uint32(gid)
		case 4:
			u.Gecos = p
		case 5:
			u.Home = p
		case 6:
			u.Shell = p
		}
	}

	return u
}
