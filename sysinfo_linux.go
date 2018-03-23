// +build linux

// Copyright 2017 Google Inc.
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
	"os/user"
)

// User will obtain the current user from the OS.
func User() (string, error) {
	u, err := user.Current()
	if err != nil {
		return "", errors.New("could not determine the user")
	}
	return u.Username, nil
}

// These are retained for build compatibility
const (
	StandaloneWorkstation = iota
	MemberWorkstation
	StandaloneServer
	MemberServer
	BackupDomainController
	PrimaryDomainController
)

// ComputerInfo is a stub for build compatibility
type ComputerInfo struct {
	DNSHostName       string
	Domain            string
	DomainRole        int
	Model             string
	Vendor            string
	UUID              string
	IdentifyingNumber string
	MACAddress        string
}

// CompInfo is a stub for build compatibility.
func CompInfo() (ComputerInfo, error) {
	return ComputerInfo{}, nil
}

// CompProdInfo is a stub for build compatibility.
func CompProdInfo() (ComputerInfo, error) {
	return ComputerInfo{}, nil
}

// NetInfo is a stub for build compatibility.
func NetInfo() ([]string, error) {
	return nil, nil
}
