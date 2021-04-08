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

	"k8s.io/ip-masq-agent/cmd/ip-masq-agent/testing/fakefs"
	utiliptables "k8s.io/kubernetes/pkg/util/iptables"
	iptest "k8s.io/kubernetes/pkg/util/iptables/testing"
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
		config:    &MasqConfig{},
		iptables:  iptest.NewFake(),
		ip6tables: iptest.NewFake(),
	}
}

// Returns a MasqConfig with config values that are the same as the default values when the
// noMasqueradeAllReservedRangesFlag is false.
func NewMasqConfigNoReservedRanges() *MasqConfig {
	return &MasqConfig{
		NonMasqueradeCIDRs: []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"},
		MasqLinkLocal:      false,
		ResyncInterval:     Duration(60 * time.Second),
	}
}

// Returns a MasqConfig with config values that are the same as the default values when the
// noMasqueradeAllReservedRangesFlag is true.
func NewMasqConfigWithReservedRanges() *MasqConfig {
	return &MasqConfig{
		NonMasqueradeCIDRs: []string{
			"10.0.0.0/8",
			"172.16.0.0/12",
			"192.168.0.0/16",
			"100.64.0.0/10",
			"192.0.0.0/24",
			"192.0.2.0/24",
			"192.88.99.0/24",
			"198.18.0.0/15",
			"198.51.100.0/24",
			"203.0.113.0/24",
			"240.0.0.0/4"},
		MasqLinkLocal:  false,
		ResyncInterval: Duration(60 * time.Second),
	}
}

func NewMasqConfigWithSnat() *MasqConfig {
	return &MasqConfig{
		NonMasqueradeCIDRs: []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"},
		MasqLinkLocal:      false,
		ResyncInterval:     Duration(60 * time.Second),
		SnatTarget:         "192.168.0.42",
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
	{NewMasqConfigNoReservedRanges(), nil},
	// CIDR that doesn't match regex
	{&MasqConfig{NonMasqueradeCIDRs: []string{"abcdefg"}}, fmt.Errorf(cidrParseErrFmt, "abcdefg", fmt.Errorf("invalid CIDR address: %s", "abcdefg"))},
	// Multiple CIDRs, one doesn't match regex
	{&MasqConfig{NonMasqueradeCIDRs: []string{"10.0.0.0/8", "abcdefg"}}, fmt.Errorf(cidrParseErrFmt, "abcdefg", fmt.Errorf("invalid CIDR address: %s", "abcdefg"))},
	// CIDR that matches regex but can't be parsed
	{&MasqConfig{NonMasqueradeCIDRs: []string{"10.256.0.0/16"}}, fmt.Errorf(cidrParseErrFmt, "10.256.0.0/16", fmt.Errorf("invalid CIDR address: %s", "10.256.0.0/16"))},
	// Misaligned CIDR
	{&MasqConfig{NonMasqueradeCIDRs: []string{"10.0.0.1/8"}}, fmt.Errorf(cidrAlignErrFmt, "10.0.0.1/8", "10.0.0.1", "10.0.0.0/8")},
	// invalid SNAT target IP
	{&MasqConfig{SnatTarget: "foo"}, fmt.Errorf("SnatTarget is not a valid IP (%q)", "foo")},
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
	{"valid yaml file, all keys", fakefs.StringFS{File: `
nonMasqueradeCIDRs:
  - 172.16.0.0/12
  - 10.0.0.0/8
masqLinkLocal: true
resyncInterval: 5s
snatTarget: 192.168.0.42
`}, nil, &MasqConfig{
		NonMasqueradeCIDRs: []string{"172.16.0.0/12", "10.0.0.0/8"},
		MasqLinkLocal:      true,
		ResyncInterval:     Duration(5 * time.Second),
		SnatTarget:         "192.168.0.42"}},

	{"valid yaml file, just nonMasqueradeCIDRs", fakefs.StringFS{File: `
nonMasqueradeCIDRs:
  - 192.168.0.0/16
`}, nil, &MasqConfig{
		NonMasqueradeCIDRs: []string{"192.168.0.0/16"},
		MasqLinkLocal:      NewMasqConfigNoReservedRanges().MasqLinkLocal,
		ResyncInterval:     NewMasqConfigNoReservedRanges().ResyncInterval}},

	{"valid yaml file, just masqLinkLocal", fakefs.StringFS{File: `
masqLinkLocal: true
`}, nil, &MasqConfig{
		NonMasqueradeCIDRs: NewMasqConfigNoReservedRanges().NonMasqueradeCIDRs,
		MasqLinkLocal:      true,
		ResyncInterval:     NewMasqConfigNoReservedRanges().ResyncInterval}},

	{"valid yaml file, just resyncInterval", fakefs.StringFS{File: `
resyncInterval: 5m
`}, nil, &MasqConfig{
		NonMasqueradeCIDRs: NewMasqConfigNoReservedRanges().NonMasqueradeCIDRs,
		MasqLinkLocal:      NewMasqConfigNoReservedRanges().MasqLinkLocal,
		ResyncInterval:     Duration(5 * time.Minute)}},

	{"valid yaml file, just snatTarget", fakefs.StringFS{File: `
snatTarget: 192.168.0.42
`}, nil, &MasqConfig{
		NonMasqueradeCIDRs: NewMasqConfigNoReservedRanges().NonMasqueradeCIDRs,
		MasqLinkLocal:      NewMasqConfigNoReservedRanges().MasqLinkLocal,
		ResyncInterval:     NewMasqConfigNoReservedRanges().ResyncInterval,
		SnatTarget:         "192.168.0.42"}},
	// invalid yaml
	{"invalid yaml file", fakefs.StringFS{File: `*`}, fmt.Errorf("yaml: did not find expected alphabetic or numeric character"), NewMasqConfigNoReservedRanges()},

	// valid json
	{"valid json file, all keys", fakefs.StringFS{File: `
{
  "nonMasqueradeCIDRs": ["172.16.0.0/12", "10.0.0.0/8"],
  "masqLinkLocal": true,
  "resyncInterval": "5s"
}
`},
		nil, &MasqConfig{
			NonMasqueradeCIDRs: []string{"172.16.0.0/12", "10.0.0.0/8"},
			MasqLinkLocal:      true,
			ResyncInterval:     Duration(5 * time.Second)}},

	{"valid json file, just nonMasqueradeCIDRs", fakefs.StringFS{File: `
{
	"nonMasqueradeCIDRs": ["192.168.0.0/16"]
}
`},
		nil, &MasqConfig{
			NonMasqueradeCIDRs: []string{"192.168.0.0/16"},
			MasqLinkLocal:      NewMasqConfigNoReservedRanges().MasqLinkLocal,
			ResyncInterval:     NewMasqConfigNoReservedRanges().ResyncInterval}},

	{"valid json file, just masqLinkLocal", fakefs.StringFS{File: `
{
	"masqLinkLocal": true
}
`},
		nil, &MasqConfig{
			NonMasqueradeCIDRs: NewMasqConfigNoReservedRanges().NonMasqueradeCIDRs,
			MasqLinkLocal:      true,
			ResyncInterval:     NewMasqConfigNoReservedRanges().ResyncInterval}},

	{"valid json file, just resyncInterval", fakefs.StringFS{File: `
{
	"resyncInterval": "5m"
}
`},
		nil, &MasqConfig{
			NonMasqueradeCIDRs: NewMasqConfigNoReservedRanges().NonMasqueradeCIDRs,
			MasqLinkLocal:      NewMasqConfigNoReservedRanges().MasqLinkLocal,
			ResyncInterval:     Duration(5 * time.Minute)}},

	// invalid json
	{"invalid json file", fakefs.StringFS{File: `{*`}, fmt.Errorf("invalid character '*' looking for beginning of object key string"), NewMasqConfigNoReservedRanges()},

	// file does not exist
	{"no config file", fakefs.NotExistFS{}, nil, NewMasqConfigNoReservedRanges()}, // If the file does not exist, defaults should be used

	// valid json with ipv6 non masquerade cidr
	{"valid json file, all keys with ipv6 cidr", fakefs.StringFS{File: `
		{
		  "nonMasqueradeCIDRs": ["172.16.0.0/12", "10.0.0.0/8", "fc00::/7"],
		  "masqLinkLocal": true,
		  "resyncInterval": "5s"
		}
		`},
		nil, &MasqConfig{
			NonMasqueradeCIDRs: []string{"172.16.0.0/12", "10.0.0.0/8", "fc00::/7"},
			MasqLinkLocal:      true,
			ResyncInterval:     Duration(5 * time.Second)}},
}

// tests MasqDaemon.syncConfig
func TestSyncConfig(t *testing.T) {
	for _, tt := range syncConfigTests {
		flag.Set("enable-ipv6", "true")
		m := NewFakeMasqDaemon()
		m.config = NewMasqConfigNoReservedRanges()
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
	var syncMasqRulesTests = []struct {
		desc string      // human readable description of the test
		cfg  *MasqConfig // Masq configuration to use
		err  error       // expected error, if any. If nil, no error expected
		want string      // String expected to be sent to iptables-restore
	}{
		{
			desc: "empty config",
			cfg:  &MasqConfig{},
			want: `*nat
:` + string(masqChain) + ` - [0:0]
-A ` + string(masqChain) + ` ` + nonMasqRuleComment + ` -d 169.254.0.0/16 -j RETURN
-A ` + string(masqChain) + ` ` + masqRuleComment + ` -j MASQUERADE
COMMIT
`,
		},
		{
			desc: "default config masquerading reserved ranges",
			cfg:  NewMasqConfigNoReservedRanges(),
			want: `*nat
:` + string(masqChain) + ` - [0:0]
-A ` + string(masqChain) + ` ` + nonMasqRuleComment + ` -d 169.254.0.0/16 -j RETURN
-A ` + string(masqChain) + ` ` + nonMasqRuleComment + ` -d 10.0.0.0/8 -j RETURN
-A ` + string(masqChain) + ` ` + nonMasqRuleComment + ` -d 172.16.0.0/12 -j RETURN
-A ` + string(masqChain) + ` ` + nonMasqRuleComment + ` -d 192.168.0.0/16 -j RETURN
-A ` + string(masqChain) + ` ` + masqRuleComment + ` -j MASQUERADE
COMMIT
`,
		},
		{
			desc: "default config not masquerading reserved ranges",
			cfg:  NewMasqConfigWithReservedRanges(),
			want: `*nat
:` + string(masqChain) + ` - [0:0]
-A ` + string(masqChain) + ` ` + nonMasqRuleComment + ` -d 169.254.0.0/16 -j RETURN
-A ` + string(masqChain) + ` ` + nonMasqRuleComment + ` -d 10.0.0.0/8 -j RETURN
-A ` + string(masqChain) + ` ` + nonMasqRuleComment + ` -d 172.16.0.0/12 -j RETURN
-A ` + string(masqChain) + ` ` + nonMasqRuleComment + ` -d 192.168.0.0/16 -j RETURN
-A ` + string(masqChain) + ` ` + nonMasqRuleComment + ` -d 100.64.0.0/10 -j RETURN
-A ` + string(masqChain) + ` ` + nonMasqRuleComment + ` -d 192.0.0.0/24 -j RETURN
-A ` + string(masqChain) + ` ` + nonMasqRuleComment + ` -d 192.0.2.0/24 -j RETURN
-A ` + string(masqChain) + ` ` + nonMasqRuleComment + ` -d 192.88.99.0/24 -j RETURN
-A ` + string(masqChain) + ` ` + nonMasqRuleComment + ` -d 198.18.0.0/15 -j RETURN
-A ` + string(masqChain) + ` ` + nonMasqRuleComment + ` -d 198.51.100.0/24 -j RETURN
-A ` + string(masqChain) + ` ` + nonMasqRuleComment + ` -d 203.0.113.0/24 -j RETURN
-A ` + string(masqChain) + ` ` + nonMasqRuleComment + ` -d 240.0.0.0/4 -j RETURN
-A ` + string(masqChain) + ` ` + masqRuleComment + ` -j MASQUERADE
COMMIT
`,
		},
		{
			desc: "config has ipv4 and ipv6 non masquerade cidr",
			cfg: &MasqConfig{
				NonMasqueradeCIDRs: []string{
					"10.244.0.0/16",
					"fc00::/7",
				},
			},
			want: `*nat
:` + string(masqChain) + ` - [0:0]
-A ` + string(masqChain) + ` ` + nonMasqRuleComment + ` -d 169.254.0.0/16 -j RETURN
-A ` + string(masqChain) + ` ` + nonMasqRuleComment + ` -d 10.244.0.0/16 -j RETURN
-A ` + string(masqChain) + ` ` + masqRuleComment + ` -j MASQUERADE
COMMIT
`,
		},
		{
			desc: "config has snatTarget: 192.168.0.42",
			cfg:  &MasqConfig{SnatTarget: "192.168.0.42"},
			want: `*nat
:` + string(masqChain) + ` - [0:0]
-A ` + string(masqChain) + ` ` + nonMasqRuleComment + ` -d 169.254.0.0/16 -j RETURN
-A ` + string(masqChain) + ` ` + snatRuleComment + ` -j SNAT --to-source 192.168.0.42
COMMIT
`,
		},
	}

	for _, tt := range syncMasqRulesTests {
		t.Run(tt.desc, func(t *testing.T) {
			m := NewFakeMasqDaemon()
			m.config = tt.cfg
			m.syncMasqRules()
			fipt, ok := m.iptables.(*iptest.FakeIPTables)
			if !ok {
				t.Errorf("MasqDaemon wasn't using the expected iptables mock")
			}
			if string(fipt.Lines) != tt.want {
				t.Errorf("syncMasqRules wrote %q, want %q", string(fipt.Lines), tt.want)
			}
		})
	}
}

// tests MasqDaemon.syncMasqRulesIPv6
func TestSyncMasqRulesIPv6(t *testing.T) {
	var syncMasqRulesIPv6Tests = []struct {
		desc string      // human readable description of the test
		cfg  *MasqConfig // Masq configuration to use
		err  error       // expected error, if any. If nil, no error expected
		want string      // String expected to be sent to iptables-restore
	}{
		{
			desc: "empty config",
			cfg:  &MasqConfig{},
			want: `*nat
:` + string(masqChain) + ` - [0:0]
-A ` + string(masqChain) + ` ` + nonMasqRuleComment + ` -d fe80::/10 -j RETURN
-A ` + string(masqChain) + ` ` + masqRuleComment + ` -j MASQUERADE
COMMIT
`,
		},
		{
			desc: "config has ipv4 and ipv6 non masquerade cidr",
			cfg: &MasqConfig{
				NonMasqueradeCIDRs: []string{
					"10.244.0.0/16",
					"fc00::/7",
				},
			},
			want: `*nat
:` + string(masqChain) + ` - [0:0]
-A ` + string(masqChain) + ` ` + nonMasqRuleComment + ` -d fe80::/10 -j RETURN
-A ` + string(masqChain) + ` ` + nonMasqRuleComment + ` -d fc00::/7 -j RETURN
-A ` + string(masqChain) + ` ` + masqRuleComment + ` -j MASQUERADE
COMMIT
`,
		},
		{
			desc: "config has masqLinkLocalIPv6: true",
			cfg:  &MasqConfig{MasqLinkLocalIPv6: true},
			want: `*nat
:` + string(masqChain) + ` - [0:0]
-A ` + string(masqChain) + ` ` + masqRuleComment + ` -j MASQUERADE
COMMIT
`,
		},
	}

	for _, tt := range syncMasqRulesIPv6Tests {
		t.Run(tt.desc, func(t *testing.T) {
			flag.Set("enable-ipv6", "true")
			m := NewFakeMasqDaemon()
			m.config = tt.cfg
			m.syncMasqRulesIPv6()
			fipt6, ok := m.ip6tables.(*iptest.FakeIPTables)
			if !ok {
				t.Errorf("MasqDaemon wasn't using the expected iptables mock")
			}
			if string(fipt6.Lines) != tt.want {
				t.Errorf("syncMasqRulesIPv6 wrote %q, want %q", string(fipt6.Lines), tt.want)
			}
		})
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
	var writeNonMasqRuleTests = []struct {
		desc string
		cidr string
		want string
	}{
		{
			desc: "with ipv4 non masquerade cidr",
			cidr: "10.0.0.0/8",
			want: string(utiliptables.Append) + " " + string(masqChain) +
				` -m comment --comment "ip-masq-agent: local traffic is not subject to MASQUERADE"` +
				" -d 10.0.0.0/8 -j RETURN\n",
		},
		{
			desc: "with ipv6 non masquerade cidr",
			cidr: "fc00::/7",
			want: string(utiliptables.Append) + " " + string(masqChain) +
				` -m comment --comment "ip-masq-agent: local traffic is not subject to MASQUERADE"` +
				" -d fc00::/7 -j RETURN\n",
		},
	}

	for _, tt := range writeNonMasqRuleTests {
		t.Run(tt.desc, func(t *testing.T) {
			lines := bytes.NewBuffer(nil)
			writeNonMasqRule(lines, tt.cidr)

			s, err := lines.ReadString('\n')
			if err != nil {
				t.Error("writeRule did not append a newline")
			}
			if s != tt.want {
				t.Errorf("writeNonMasqRule(lines, "+tt.cidr+"):\n   got: %q\n  want: %q", s, tt.want)
			}
		})
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
