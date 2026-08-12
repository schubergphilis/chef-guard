//
// Copyright 2026, Schuberg Philis
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
//

package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRemarshalConfigRedactsPrivateKey(t *testing.T) {
	body := []byte(`{
		"name": "myclient",
		"public_key": "-----BEGIN PUBLIC KEY-----\nabc\n-----END PUBLIC KEY-----\n",
		"private_key": "-----BEGIN RSA PRIVATE KEY-----\nsecret\n-----END RSA PRIVATE KEY-----\n"
	}`)

	out, err := remarshalConfig("POST", body)
	if err != nil {
		t.Fatalf("remarshalConfig returned an error: %s", err)
	}

	if strings.Contains(string(out), "private_key") || strings.Contains(string(out), "secret") {
		t.Fatalf("expected private_key to be redacted, got: %s", out)
	}

	var config map[string]interface{}
	if err := json.Unmarshal(out, &config); err != nil {
		t.Fatalf("failed to unmarshal result: %s", err)
	}
	if config["name"] != "myclient" {
		t.Fatalf("expected name to be preserved, got: %v", config["name"])
	}
	if _, found := config["public_key"]; !found {
		t.Fatalf("expected public_key to be preserved")
	}
}

func TestRemarshalConfigStripsAutomatic(t *testing.T) {
	body := []byte(`{
		"name": "mynode",
		"automatic": {"foo": "bar"},
		"normal": {"baz": "qux"}
	}`)

	out, err := remarshalConfig("PUT", body)
	if err != nil {
		t.Fatalf("remarshalConfig returned an error: %s", err)
	}

	var config map[string]interface{}
	if err := json.Unmarshal(out, &config); err != nil {
		t.Fatalf("failed to unmarshal result: %s", err)
	}
	if _, found := config["automatic"]; found {
		t.Fatalf("expected automatic to be stripped, got: %s", out)
	}
	if _, found := config["normal"]; !found {
		t.Fatalf("expected normal to be preserved")
	}
}

func TestRemarshalConfigPassthroughWhenNoSensitiveFields(t *testing.T) {
	body := []byte(`{"name": "myrole"}`)

	out, err := remarshalConfig("POST", body)
	if err != nil {
		t.Fatalf("remarshalConfig returned an error: %s", err)
	}

	var config map[string]interface{}
	if err := json.Unmarshal(out, &config); err != nil {
		t.Fatalf("failed to unmarshal result: %s", err)
	}
	if config["name"] != "myrole" {
		t.Fatalf("expected name to be preserved, got: %v", config["name"])
	}
}

func TestRemarshalConfigDeletePassesThrough(t *testing.T) {
	body := []byte(`{"name": "myclient", "private_key": "secret"}`)

	out, err := remarshalConfig("DELETE", body)
	if err != nil {
		t.Fatalf("remarshalConfig returned an error: %s", err)
	}

	if string(out) != string(body)+"\n" {
		t.Fatalf("expected body to be returned unchanged (plus trailing newline), got: %s", out)
	}
}
