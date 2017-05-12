/*
Copyright 2017 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or impliem.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"reflect"
	"testing"
	"time"

	utiliptables "k8s.io/kubernetes/pkg/util/iptables"
	iptest "k8s.io/kubernetes/pkg/util/iptables/testing"
	"k8s.io/non-masquerade-daemon/cmd/non-masquerade-daemon/testing/fakefs"
)

// turn off glog logging during tests to avoid clutter in output
func TestMain(m *testing.M) {
	flag.Set("logtostderr", "false")
	ec := m.Run()
	os.Exit(ec)
}

// returns a MasqDaemon with empty config values and a fake iptables interface
func NewFakeMasqDaemon() *MasqDaemon {
	return &MasqDaemon{
		config:   &MasqConfig{},
		iptables: iptest.NewFake(),
	}
}

// specs for testing config validation
var validateConfigTests = []struct {
	cfg *MasqConfig
	err error
}{
	// Empty CIDR List
	{&MasqConfig{}, nil},
	// Default Config
	{NewMasqConfig(), nil},
	// CIDR that doesn't match regex
	{&MasqConfig{NonMasqueradeCIDRs: []string{"abcdefg"}}, fmt.Errorf(cidrMatchErrFmt, "abcdefg", cidrRE)},
	// Multiple CIDRs, one doesn't match regex
	{&MasqConfig{NonMasqueradeCIDRs: []string{"10.0.0.0/8", "abcdefg"}}, fmt.Errorf(cidrMatchErrFmt, "abcdefg", cidrRE)},
	// CIDR that matches regex but can't be parsed
	{&MasqConfig{NonMasqueradeCIDRs: []string{"10.256.0.0/16"}}, fmt.Errorf(cidrParseErrFmt, "10.256.0.0/16", fmt.Errorf("invalid CIDR address: 10.256.0.0/16"))},
	// Misaligned CIDR
	{&MasqConfig{NonMasqueradeCIDRs: []string{"10.0.0.1/8"}}, fmt.Errorf(cidrAlignErrFmt, "10.0.0.1/8", "10.0.0.1", "10.0.0.0/8")},
}

// tests the MasqConfig.validate method
func TestConfigValidate(t *testing.T) {
	for _, tt := range validateConfigTests {
		err := tt.cfg.validate()
		if errorToString(err) != errorToString(tt.err) {
			t.Errorf("%+v.validate() => %s, want %s", tt.cfg, errorToString(err), errorToString(tt.err))
		}
	}
}

// specs for testing loading config from fs
var syncConfigTests = []struct {
	desc string            // human readable description of the fs used for the test e.g. "no config file"
	fs   fakefs.FileSystem // filesystem interface
	err  error             // expected error from MasqDaemon.syncConfig(fs)
	cfg  *MasqConfig       // expected values of the configuration after loading from fs
}{
	// valid yaml
	{"valid yaml file, all keys", fakefs.StringFS{`
nonMasqueradeCIDRs:
  - 172.16.0.0/12
  - 10.0.0.0/8
linkLocal: false
resyncInterval: 5s
`}, nil, &MasqConfig{
		NonMasqueradeCIDRs: []string{"172.16.0.0/12", "10.0.0.0/8"},
		LinkLocal:          false,
		ResyncInterval:     Duration(5 * time.Second)}},

	{"valid yaml file, just nonMasqueradeCIDRs", fakefs.StringFS{`
nonMasqueradeCIDRs:
  - 192.168.0.0/16
`}, nil, &MasqConfig{
		NonMasqueradeCIDRs: []string{"192.168.0.0/16"},
		LinkLocal:          NewMasqConfig().LinkLocal,
		ResyncInterval:     NewMasqConfig().ResyncInterval}},

	{"valid yaml file, just linkLocal", fakefs.StringFS{`
linkLocal: false
`}, nil, &MasqConfig{
		NonMasqueradeCIDRs: NewMasqConfig().NonMasqueradeCIDRs,
		LinkLocal:          false,
		ResyncInterval:     NewMasqConfig().ResyncInterval}},

	{"valid yaml file, just resyncInterval", fakefs.StringFS{`
resyncInterval: 5m
`}, nil, &MasqConfig{
		NonMasqueradeCIDRs: NewMasqConfig().NonMasqueradeCIDRs,
		LinkLocal:          NewMasqConfig().LinkLocal,
		ResyncInterval:     Duration(5 * time.Minute)}},

	// invalid yaml
	{"invalid yaml file", fakefs.StringFS{`*`}, fmt.Errorf("yaml: did not find expected alphabetic or numeric character"), NewMasqConfig()},

	// valid json
	{"valid json file, all keys", fakefs.StringFS{`
{
  "nonMasqueradeCIDRs": ["172.16.0.0/12", "10.0.0.0/8"],
  "linkLocal": false,
  "resyncInterval": "5s"
}
`},
		nil, &MasqConfig{
			NonMasqueradeCIDRs: []string{"172.16.0.0/12", "10.0.0.0/8"},
			LinkLocal:          false,
			ResyncInterval:     Duration(5 * time.Second)}},

	{"valid json file, just nonMasqueradeCIDRs", fakefs.StringFS{`
{
	"nonMasqueradeCIDRs": ["192.168.0.0/16"]
}
`},
		nil, &MasqConfig{
			NonMasqueradeCIDRs: []string{"192.168.0.0/16"},
			LinkLocal:          NewMasqConfig().LinkLocal,
			ResyncInterval:     NewMasqConfig().ResyncInterval}},

	{"valid json file, just linkLocal", fakefs.StringFS{`
{
	"linkLocal": false}
`},
		nil, &MasqConfig{
			NonMasqueradeCIDRs: NewMasqConfig().NonMasqueradeCIDRs,
			LinkLocal:          false,
			ResyncInterval:     NewMasqConfig().ResyncInterval}},

	{"valid json file, just resyncInterval", fakefs.StringFS{`
{
	"resyncInterval": "5m"
}
`},
		nil, &MasqConfig{
			NonMasqueradeCIDRs: NewMasqConfig().NonMasqueradeCIDRs,
			LinkLocal:          NewMasqConfig().LinkLocal,
			ResyncInterval:     Duration(5 * time.Minute)}},

	// invalid json
	{"invalid json file", fakefs.StringFS{`{*`}, fmt.Errorf("invalid character '*' looking for beginning of object key string"), NewMasqConfig()},

	// file does not exist
	{"no config file", fakefs.NotExistFS{}, nil, NewMasqConfig()}, // If the file does not exist, defaults should be used
}

// tests MasqDaemon.syncConfig
func TestSyncConfig(t *testing.T) {
	for _, tt := range syncConfigTests {
		m := NewFakeMasqDaemon()
		m.config = NewMasqConfig()
		err := m.syncConfig(tt.fs)
		if errorToString(err) != errorToString(tt.err) {
			t.Errorf("MasqDaemon.syncConfig(fs: %s) => %s, want %s", tt.desc, errorToString(err), errorToString(tt.err))
		} else if !reflect.DeepEqual(m.config, tt.cfg) {
			t.Errorf("MasqDaemon.syncConfig(fs: %s) loaded as %+v, want %+v", tt.desc, m.config, tt.cfg)
		}
	}
}

// tests MasqDaemon.syncMasqRules
func TestSyncMasqRules(t *testing.T) {
	// empty config
	m := NewFakeMasqDaemon()
	want := `*nat
:` + string(masqChain) + ` - [0:0]
-A ` + string(masqChain) + ` ` + masqRuleComment + ` -m addrtype ! --dst-type LOCAL -j MASQUERADE
COMMIT
`
	m.syncMasqRules()
	fipt, ok := m.iptables.(*iptest.FakeIPTables)
	if !ok {
		t.Errorf("MasqDaemon wasn't using the expected iptables mock")
	}
	if string(fipt.Lines) != want {
		t.Errorf("syncMasqRules wrote %q, want %q", string(fipt.Lines), want)
	}

	// default config
	m = NewFakeMasqDaemon()
	m.config = NewMasqConfig()
	want = `*nat
:` + string(masqChain) + ` - [0:0]
-A ` + string(masqChain) + ` ` + nonMasqRuleComment + ` -m addrtype ! --dst-type LOCAL -d 169.254.0.0/16 -j RETURN
-A ` + string(masqChain) + ` ` + nonMasqRuleComment + ` -m addrtype ! --dst-type LOCAL -d 10.0.0.0/8 -j RETURN
-A ` + string(masqChain) + ` ` + nonMasqRuleComment + ` -m addrtype ! --dst-type LOCAL -d 172.16.0.0/12 -j RETURN
-A ` + string(masqChain) + ` ` + nonMasqRuleComment + ` -m addrtype ! --dst-type LOCAL -d 192.168.0.0/16 -j RETURN
-A ` + string(masqChain) + ` ` + masqRuleComment + ` -m addrtype ! --dst-type LOCAL -j MASQUERADE
COMMIT
`
	m.syncMasqRules()
	fipt, ok = m.iptables.(*iptest.FakeIPTables)
	if !ok {
		t.Errorf("MasqDaemon wasn't using the expected iptables mock")
	}
	if string(fipt.Lines) != want {
		t.Errorf("syncMasqRules wrote %q, want %q", string(fipt.Lines), want)
	}
}

// TODO(mtaufen): switch to an iptables mock that allows us to check the results of EnsureRule
// tests m.ensurePostroutingJump
func TestEnsurePostroutingJump(t *testing.T) {
	m := NewFakeMasqDaemon()
	if err := m.ensurePostroutingJump(); err != nil {
		t.Errorf("error: %v", err)
	}
}

// tests writeNonMasqRule
func TestWriteNonMasqRule(t *testing.T) {
	lines := bytes.NewBuffer(nil)
	cidr := "10.0.0.0/8"
	want := string(utiliptables.Append) + " " + string(masqChain) +
		` -m comment --comment "non-masquerade-daemon: cluster-local traffic should not be subject to MASQUERADE"` +
		" -m addrtype ! --dst-type LOCAL -d " + cidr + " -j RETURN\n"
	writeNonMasqRule(lines, cidr)

	s, err := lines.ReadString('\n')
	if err != nil {
		t.Error("writeRule did not append a newline")
	}
	if s != want {
		t.Errorf("writeNonMasqRule(lines, "+cidr+") wrote %q, want %q", s, want)
	}
}

// tests writeRule
func TestWriteRule(t *testing.T) {
	lines := bytes.NewBuffer(nil)
	want := string(utiliptables.Append) + " " + string(masqChain) +
		" -m comment --comment \"test writing a rule\"\n"
	writeRule(lines, utiliptables.Append, masqChain, "-m", "comment", "--comment", `"test writing a rule"`)

	s, err := lines.ReadString('\n')
	if err != nil {
		t.Error("writeRule did not append a newline")
	}
	if s != want {
		t.Errorf("writeRule(lines, pos, chain, \"-m\", \"comment\", \"--comment\", `\"test writing a rule\"`) wrote %q, want %q", s, want)
	}
}

// tests writeLine
func TestWriteLine(t *testing.T) {
	lines := bytes.NewBuffer(nil)
	want := "a b c\n"

	writeLine(lines, "a", "b", "c")

	s, err := lines.ReadString('\n')
	if err != nil {
		t.Error("writeLine did not append a newline")
	}
	if s != want {
		t.Errorf("writeLine(lines, \"a\", \"b\", \"c\") wrote %q, want %q", s, want)
	}
}

// convert error to string, while also handling nil errors
func errorToString(err error) string {
	if err == nil {
		return "nil error"
	}
	return fmt.Sprintf("error %q", err.Error())
}
