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
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
	"k8s.io/ip-masq-agent/cmd/ip-masq-agent/testing/fakefs"
	"k8s.io/kubernetes/pkg/util/iptables"
	utiliptables "k8s.io/kubernetes/pkg/util/iptables"
	iptest "k8s.io/kubernetes/pkg/util/iptables/testing"
)

func strArrayPtr(s []string) *[]string {
	return &s
}

// turn off glog logging during tests to avoid clutter in output
func TestMain(m *testing.M) {
	flag.Set("logtostderr", "false")
	flag.Set("masq-chain", "IP-MASQ-AGENT")
	ec := m.Run()
	os.Exit(ec)
}

// returns a MasqDaemon with empty config values and a fake iptables interface
func NewFakeMasqDaemon() *MasqDaemon {
	iptables := iptest.NewFake()
	iptables.Dump = &iptest.IPTablesDump{
		Tables: []iptest.Table{
			{
				Name: utiliptables.TableNAT,
				Chains: []iptest.Chain{
					{Name: utiliptables.ChainPostrouting},
				},
			},
		},
	}
	ip6tables := iptest.NewIPv6Fake()
	ip6tables.Dump = &iptest.IPTablesDump{
		Tables: []iptest.Table{
			{
				Name: utiliptables.TableNAT,
				Chains: []iptest.Chain{
					{Name: utiliptables.ChainPostrouting},
				},
			},
		},
	}
	return &MasqDaemon{
		config:    NewMasqConfig(MasqConfig{}),
		iptables:  iptest.NewFake(),
		ip6tables: iptest.NewFake(),
	}
}

func intoResyncInterval(dur Duration) *Duration {
	return &dur
}

func TestNewMasqConfigDefault(t *testing.T) {
	m := NewMasqConfig(MasqConfig{})
	if !reflect.DeepEqual(m.DoNotMasqueradeCIDRs(V4), []string{"169.254.0.0/16", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}) {
		t.Errorf("Unexpected default NonMasqueradeCIDRs: %v", m.DoNotMasqueradeCIDRs(V4))
	}
	if m.CidrLimit != 64 {
		t.Error("Unexpected default CidrLimit")
	}
	if m.MasqLinkLocal == nil {
		t.Error("Unexpected default MasqLinkLocal")
	}
	if m.MasqLinkLocalIPv6 == nil {
		t.Error("Unexpected default MasqLinkLocalIPv6")
	}
	if m.OptionalResyncInterval == nil {
		t.Error("Unexpected default OptionalResyncInterval")
	}
	myMinute, _ := time.ParseDuration("60s")
	if time.Duration(*m.OptionalResyncInterval).Nanoseconds() != myMinute.Nanoseconds() {
		t.Error("Unexpected default OptionalResyncInterval")
	}
	if m.OutputInterface != nil {
		t.Error("Unexpected default OutputInterface")
	}
	if m.OutputAddress != nil {
		t.Error("Unexpected default OutputAddress")
	}
	if m.OutputAddressIPv6 != nil {
		t.Error("Unexpected default OutputAddressIPv6")
	}
	if m.MasqueradeAllReservedRanges != false {
		t.Error("Unexpected default MasqueradeAllReservedRanges")
	}
	if m.MasqChain == nil {
		t.Error("Unexpected default MasqChain")
	}
	if *m.MasqChain != "IP-MASQ-AGENT" {
		t.Error("Unexpected default MasqChain")
	}
}

func TestNewMasqConfigWithReservedRanges(t *testing.T) {
	m := NewMasqConfig(MasqConfig{
		MasqueradeAllReservedRanges: true,
	})
	if !reflect.DeepEqual(m.DoNotMasqueradeCIDRs(V4), []string{
		"169.254.0.0/16",
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
		"240.0.0.0/4",
	}) {
		t.Errorf("Unexpected default NonMasqueradeCIDRs")
	}
}

func TestNewMasqConfig(t *testing.T) {
	myOutputInterface := "eth0"
	myOutputAddress := "1.1.1.1"
	myOutputAddressIPv6 := "fc00::dead:beef"
	m := NewMasqConfig(MasqConfig{
		NonMasqueradeCIDRs:     strArrayPtr([]string{"1.1.1.1/23"}),
		CidrLimit:              32,
		MasqLinkLocal:          boolPtr(false),
		MasqLinkLocalIPv6:      boolPtr(false),
		OptionalResyncInterval: intoResyncInterval(Duration(10 * time.Second)),
		OutputInterface:        &myOutputInterface,
		OutputAddress:          &myOutputAddress,
		OutputAddressIPv6:      &myOutputAddressIPv6,
	})
	if !reflect.DeepEqual(m.DoNotMasqueradeCIDRs(V4), []string{"1.1.1.1/23"}) {
		t.Error("Unexpected default NonMasqueradeCIDRs")
	}
	if m.CidrLimit != 32 {
		t.Error("Unexpected default CidrLimit")
	}
	if *m.MasqLinkLocal {
		t.Error("Unexpected default MasqLinkLocal")
	}
	if *m.MasqLinkLocalIPv6 {
		t.Error("Unexpected default MasqLinkLocalIPv6")
	}
	if m.OptionalResyncInterval == nil {
		t.Error("Unexpected default OptionalResyncInterval")
	}
	myMinute, _ := time.ParseDuration("10s")
	if time.Duration(*m.OptionalResyncInterval).Nanoseconds() != myMinute.Nanoseconds() {
		t.Error("Unexpected default OptionalResyncInterval")
	}
	if m.OutputInterface == nil {
		t.Error("Unexpected default OutputInterface")
	}
	if *m.OutputInterface != myOutputInterface {
		t.Error("Unexpected default OutputInterface")
	}
	if m.OutputAddress == nil {
		t.Error("Unexpected default OutputAddress")
	}
	if *m.OutputAddress != myOutputAddress {
		t.Error("Unexpected default OutputAddress")
	}
	if m.OutputAddressIPv6 == nil {
		t.Error("Unexpected default OutputAddressIPv6")
	}
	if *m.OutputAddressIPv6 != myOutputAddressIPv6 {
		t.Error("Unexpected default OutputAddressIPv6")
	}
}

func withOutputInterface(m *MasqConfig) *MasqConfig {
	out := *m
	iface := "eth0"
	out.OutputInterface = &iface
	return &out
}

func withOutputAddress(m *MasqConfig) *MasqConfig {
	out := *m
	addr := "1.2.3.4"
	out.OutputAddress = &addr
	addrv6 := "fc00::dead:beef"
	out.OutputAddressIPv6 = &addrv6
	return &out
}

type configTest struct {
	cfg *MasqConfig
	err error
}

func generateConfigTests() []configTest {
	inCfg := []configTest{
		// Empty CIDR List
		{NewMasqConfig(MasqConfig{CidrLimit: 64, MasqLinkLocalIPv6: boolPtr(false)}), nil},
		// Default Config
		{NewMasqConfig(MasqConfig{}), nil},
		// Random-Fully
		{NewMasqConfig(MasqConfig{MasqRandomFully: true}), nil},
		// CIDR that doesn't match regex
		{NewMasqConfig(MasqConfig{CidrLimit: 64, MasqLinkLocalIPv6: boolPtr(false), NonMasqueradeCIDRs: strArrayPtr([]string{"abcdefg"})}), fmt.Errorf(cidrParseErrFmt, "abcdefg", fmt.Errorf("invalid CIDR address: %s", "abcdefg"))},
		// Multiple CIDRs, one doesn't match regex
		{NewMasqConfig(MasqConfig{CidrLimit: 64, MasqLinkLocalIPv6: boolPtr(false), NonMasqueradeCIDRs: strArrayPtr([]string{"10.0.0.0/8", "abcdefg"})}), fmt.Errorf(cidrParseErrFmt, "abcdefg", fmt.Errorf("invalid CIDR address: %s", "abcdefg"))},
		// CIDR that matches regex but can't be parsed
		{NewMasqConfig(MasqConfig{CidrLimit: 64, MasqLinkLocalIPv6: boolPtr(false), NonMasqueradeCIDRs: strArrayPtr([]string{"10.256.0.0/16"})}), fmt.Errorf(cidrParseErrFmt, "10.256.0.0/16", fmt.Errorf("invalid CIDR address: %s", "10.256.0.0/16"))},
		// Misaligned CIDR
		{NewMasqConfig(MasqConfig{CidrLimit: 64, MasqLinkLocalIPv6: boolPtr(false), NonMasqueradeCIDRs: strArrayPtr([]string{"10.0.0.1/8"})}), fmt.Errorf(cidrAlignErrFmt, "10.0.0.1/8", "10.0.0.1", "10.0.0.0/8")},
	}
	out := make([]configTest, 2*len(inCfg))
	outIdx := 0
	for _, cfg := range inCfg {
		out[outIdx] = cfg
		out[outIdx+1] = configTest{withOutputInterface(cfg.cfg), cfg.err}
		outIdx += 2
	}
	return out
}

// tests the MasqConfig.validate method
func TestConfigValidate(t *testing.T) {
	for _, tt := range generateConfigTests() {
		err := tt.cfg.validate()
		if errorToString(err) != errorToString(tt.err) {
			t.Errorf("%+v.validate() => %s, want %s", tt.cfg, errorToString(err), errorToString(tt.err))
		}
	}
}

type syncConfigTest struct {
	desc string            // human readable description of the fs used for the test e.g. "no config file"
	fs   fakefs.FileSystem // filesystem interface
	err  error             // expected error from MasqDaemon.syncConfig(fs)
	cfg  *MasqConfig       // expected values of the configuration after loading from fs
}

func trimLines(in string) (out string) {
	lines := strings.Split(in, "\n")
	firstIndent := -1
	for line, str := range lines {
		if firstIndent == -1 && strings.TrimSpace(str) == "" {
			continue
		}
		if firstIndent == -1 {
			firstIndent = len(str) - len(strings.TrimLeft(str, " \t"))
		}
		lines[line] = str[firstIndent:]
	}
	out = strings.Join(lines, "\n")
	return out
}

func toOutFs(cfg syncConfigTest, applyFN func(mc *MasqConfig) *MasqConfig) (outFs fakefs.FileSystem) {
	outFs = cfg.fs
	if cfg.err == nil {
		isYaml := true
		var c MasqConfig
		yamlOrJson, _ := cfg.fs.ReadFile(configPath)
		err := yaml.Unmarshal(yamlOrJson, &c)
		if err != nil {
			isYaml = false
			if err = json.Unmarshal(yamlOrJson, &c); err != nil {
				panic(fmt.Errorf("this should be parsable:%e:%s", err, yamlOrJson))
			}
		}
		var outBytes []byte
		if isYaml {
			outBytes, err = yaml.Marshal(applyFN(&c))
		} else {
			outBytes, err = json.Marshal(applyFN(&c))
		}
		if err != nil {
			panic(fmt.Errorf("this should work:%e", err))
		}
		outFs = fakefs.StringFS{File: string(outBytes)}
	}
	return outFs
}

func appendCfg(cfg syncConfigTest, app string) string {
	out := cfg.desc
	if cfg.err == nil {
		out += app
	}
	return out
}

func generateSyncConfigTests() []syncConfigTest {
	// valid yaml
	inCfg := []syncConfigTest{
		{"valid yaml file, all keys", fakefs.StringFS{File: trimLines(`
		nonMasqueradeCIDRs:
		  - 172.16.0.0/12
		  - 10.0.0.0/8
		cidrLimit: 64
		masqLinkLocal: true
		resyncInterval: 5s
		`)}, nil, NewMasqConfig(MasqConfig{
			NonMasqueradeCIDRs:     strArrayPtr([]string{"172.16.0.0/12", "10.0.0.0/8"}),
			MasqLinkLocal:          boolPtr(true),
			OptionalResyncInterval: intoResyncInterval(Duration(5 * time.Second)),
		}),
		},

		{"valid yaml file, just nonMasqueradeCIDRs", fakefs.StringFS{File: trimLines(`
		nonMasqueradeCIDRs:
		  - 192.168.0.0/16
		`)}, nil, NewMasqConfig(MasqConfig{
			NonMasqueradeCIDRs: strArrayPtr([]string{"192.168.0.0/16"}),
		})},

		{"valid yaml file, just masqLinkLocal", fakefs.StringFS{File: trimLines(`
		masqLinkLocal: false
		`)}, nil, NewMasqConfig(MasqConfig{
			MasqLinkLocal: boolPtr(false),
		})},

		{"valid yaml file, just masqLinkLocalIPv6", fakefs.StringFS{File: trimLines(`
			masqLinkLocalIPv6: false
			`)}, nil, NewMasqConfig(MasqConfig{
			MasqLinkLocalIPv6: boolPtr(false),
		})},

		{"valid yaml file, just resyncInterval", fakefs.StringFS{File: trimLines(`
		resyncInterval: 5m
		`)}, nil, NewMasqConfig(MasqConfig{
			OptionalResyncInterval: intoResyncInterval(Duration(5 * time.Minute)),
		})},

		// invalid yaml
		{"invalid yaml file", fakefs.StringFS{File: `*`}, fmt.Errorf("error unmarshal config file: invalid character '*' looking for beginning of value:*"), NewMasqConfig(MasqConfig{})},

		// valid json
		{"valid json file, all keys", fakefs.StringFS{File: trimLines(`
		{
		  "nonMasqueradeCIDRs": ["172.16.0.0/12", "10.0.0.0/8"],
		  "masqLinkLocal": true,
		  "resyncInterval": "5s"
		}
		`)},
			nil, NewMasqConfig(MasqConfig{
				NonMasqueradeCIDRs:     strArrayPtr([]string{"172.16.0.0/12", "10.0.0.0/8"}),
				MasqLinkLocal:          boolPtr(true),
				OptionalResyncInterval: intoResyncInterval(Duration(5 * time.Second)),
			})},

		// invalid json

		{"invalid json file", fakefs.StringFS{File: `{*`}, fmt.Errorf("error unmarshal config file: invalid character '*' looking for beginning of object key string:{*"), NewMasqConfig(MasqConfig{})},

		// file does not exist
		{"no config file", fakefs.NotExistFS{}, nil, NewMasqConfig(MasqConfig{})}, // If the file does not exist, defaults should be used

		// valid json with ipv6 non masquerade cidr
		{"valid json file, all keys with ipv6 cidr", fakefs.StringFS{File: trimLines(`
				{
				  "nonMasqueradeCIDRs": ["172.16.0.0/12", "10.0.0.0/8", "fc00::/7"],
				  "masqLinkLocal": true,
				  "resyncInterval": "5s"
				}
				`)},
			nil, NewMasqConfig(MasqConfig{
				NonMasqueradeCIDRs:     strArrayPtr([]string{"172.16.0.0/12", "10.0.0.0/8", "fc00::/7"}),
				MasqLinkLocal:          boolPtr(true),
				OptionalResyncInterval: intoResyncInterval(Duration(5 * time.Second))})},
	}

	out := make([]syncConfigTest, 3*len(inCfg))
	outIdx := 0
	for _, cfg := range inCfg {
		out[outIdx] = cfg
		out[outIdx+1] = syncConfigTest{
			desc: appendCfg(cfg, "[outputInterface]"),
			fs:   toOutFs(cfg, withOutputInterface),
			err:  cfg.err,
			cfg:  withOutputInterface(cfg.cfg),
		}
		out[outIdx+2] = syncConfigTest{
			desc: appendCfg(cfg, "[outputAddress]"),
			fs:   toOutFs(cfg, withOutputAddress),
			err:  cfg.err,
			cfg:  withOutputAddress(cfg.cfg),
		}
		outIdx += 3
	}
	return out
}

func equalConfigResyncInterval(a, b *MasqConfig) bool {
	if a.OptionalResyncInterval == nil && b.OptionalResyncInterval == nil {
		return true
	}
	if a.OptionalResyncInterval == nil || b.OptionalResyncInterval == nil {
		return false
	}
	at := time.Duration(*a.OptionalResyncInterval).Nanoseconds()
	bt := time.Duration(*b.OptionalResyncInterval).Nanoseconds()
	ret := at == bt
	return ret
	// return time.Duration(*a.resyncInterval).Nanoseconds() == time.Duration(*b.resyncInterval).Nanoseconds()
}

func equalStringPtr(a, b *string) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return *a == *b
}

func equalBoolPtr(a, b *bool) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return *a == *b
}

func equalConfig(a, b *MasqConfig, addrType IpAddrType) bool {
	return reflect.DeepEqual(a.DoNotMasqueradeCIDRs(addrType), b.DoNotMasqueradeCIDRs(addrType)) &&
		a.CidrLimit == b.CidrLimit &&
		equalBoolPtr(a.MasqLinkLocal, b.MasqLinkLocal) &&
		equalBoolPtr(a.MasqLinkLocalIPv6, b.MasqLinkLocalIPv6) &&
		equalConfigResyncInterval(a, b) &&
		equalStringPtr(a.OutputInterface, b.OutputInterface) &&
		equalStringPtr(a.OutputAddress, b.OutputAddress) &&
		equalStringPtr(a.OutputAddressIPv6, b.OutputAddressIPv6) &&
		equalStringPtr((*string)(a.MasqChain), (*string)(b.MasqChain)) &&
		a.MasqueradeAllReservedRanges == b.MasqueradeAllReservedRanges
}

// tests MasqDaemon.syncConfig
func TestSyncConfig(t *testing.T) {
	for _, tt := range generateSyncConfigTests() {
		m := NewFakeMasqDaemon()
		// m.config.EnableIPv6 = true
		err := m.syncConfig(tt.fs)
		if errorToString(err) != errorToString(tt.err) {
			t.Errorf("MasqDaemon.syncConfig(fs: %s) => [%s], want [%s]", tt.desc, errorToString(err), errorToString(tt.err))
		} else if err == nil && !equalConfig(m.config, tt.cfg, BOTH) {
			equalConfig(m.config, tt.cfg, V6)
			t.Errorf("MasqDaemon.syncConfig(fs: %s) loaded as %+v, want %+v", tt.desc, m.config, tt.cfg)
		}
	}
}

type testMasqRule struct {
	desc string      // human readable description of the test
	cfg  *MasqConfig // Masq configuration to use
	// err  error       // expected error, if any. If nil, no error expected
	want string // String expected to be sent to iptables-restore
}

func applyWantOutputInterface(iface string, want string) string {
	return strings.Replace(want, "-j MASQUERADE", fmt.Sprintf("-o %s -j MASQUERADE", iface), -1)
}

func applyWantOutputAddress(address string, want string) string {
	tmp := strings.Replace(want, "subject to MASQUERADE", "subject to SNAT", -1)
	tmp = strings.Replace(tmp, "-j MASQUERADE", fmt.Sprintf("-j SNAT --to-source %s", address), -1)
	return tmp
}

func appendRulesOutput(ipv6 bool, inCfg []testMasqRule) []testMasqRule {
	out := make([]testMasqRule, 3*len(inCfg))
	outIdx := 0
	for _, cfg := range inCfg {
		out[outIdx] = cfg
		oifCfg := withOutputInterface(cfg.cfg)
		out[outIdx+1] = testMasqRule{
			desc: cfg.desc + " with output interface",
			cfg:  oifCfg,
			want: applyWantOutputInterface(*oifCfg.OutputInterface, cfg.want),
		}
		oAddrCfg := withOutputAddress(cfg.cfg)
		addr := *oAddrCfg.OutputAddress
		if ipv6 {
			addr = *oAddrCfg.OutputAddressIPv6
		}
		out[outIdx+2] = testMasqRule{
			desc: cfg.desc + " with output address",
			cfg:  oAddrCfg,
			want: applyWantOutputAddress(addr, cfg.want),
		}
		outIdx += 3
	}
	return out
}

func generateSyncMasqRulesTests() []testMasqRule {
	defaultCfg := NewMasqConfig(MasqConfig{})
	return appendRulesOutput(false, []testMasqRule{
		{
			desc: "empty config",
			cfg: NewMasqConfig(MasqConfig{
				NonMasqueradeCIDRs: strArrayPtr([]string{}),
			}),
			want: `*nat
:` + string(utiliptables.ChainPostrouting) + ` - [0:0]
:` + string(*defaultCfg.MasqChain) + ` - [0:0]
-A ` + string(utiliptables.ChainPostrouting) + ` -m comment --comment ` +
				fmt.Sprintf(postRoutingMasqChainCommentFormat, *defaultCfg.MasqChain) + ` -m addrtype ! --dst-type LOCAL -j ` + string(*defaultCfg.MasqChain) + `
-A ` + string(*defaultCfg.MasqChain) + ` ` + nonMasqRuleComment + ` -d 169.254.0.0/16 -j RETURN
-A ` + string(*defaultCfg.MasqChain) + ` ` + masqRuleComment + ` -j MASQUERADE
COMMIT
`,
		},
		{
			desc: "default config masquerading reserved ranges",
			cfg:  defaultCfg,
			want: `*nat
:` + string(utiliptables.ChainPostrouting) + ` - [0:0]
:` + string(*defaultCfg.MasqChain) + ` - [0:0]
-A ` + string(utiliptables.ChainPostrouting) + ` -m comment --comment ` +
				fmt.Sprintf(postRoutingMasqChainCommentFormat, *defaultCfg.MasqChain) + ` -m addrtype ! --dst-type LOCAL -j ` + string(*defaultCfg.MasqChain) + `
-A ` + string(*defaultCfg.MasqChain) + ` ` + nonMasqRuleComment + ` -d 169.254.0.0/16 -j RETURN
-A ` + string(*defaultCfg.MasqChain) + ` ` + nonMasqRuleComment + ` -d 10.0.0.0/8 -j RETURN
-A ` + string(*defaultCfg.MasqChain) + ` ` + nonMasqRuleComment + ` -d 172.16.0.0/12 -j RETURN
-A ` + string(*defaultCfg.MasqChain) + ` ` + nonMasqRuleComment + ` -d 192.168.0.0/16 -j RETURN
-A ` + string(*defaultCfg.MasqChain) + ` ` + masqRuleComment + ` -j MASQUERADE
COMMIT
`,
		},
		{
			desc: "default config not masquerading reserved ranges",
			cfg:  NewMasqConfig(MasqConfig{MasqueradeAllReservedRanges: true}),
			want: `*nat
:` + string(utiliptables.ChainPostrouting) + ` - [0:0]
:` + string(*defaultCfg.MasqChain) + ` - [0:0]
-A ` + string(utiliptables.ChainPostrouting) + ` -m comment --comment ` +
				fmt.Sprintf(postRoutingMasqChainCommentFormat, *defaultCfg.MasqChain) + ` -m addrtype ! --dst-type LOCAL -j ` + string(*defaultCfg.MasqChain) + `
-A ` + string(*defaultCfg.MasqChain) + ` ` + nonMasqRuleComment + ` -d 169.254.0.0/16 -j RETURN
-A ` + string(*defaultCfg.MasqChain) + ` ` + nonMasqRuleComment + ` -d 10.0.0.0/8 -j RETURN
-A ` + string(*defaultCfg.MasqChain) + ` ` + nonMasqRuleComment + ` -d 172.16.0.0/12 -j RETURN
-A ` + string(*defaultCfg.MasqChain) + ` ` + nonMasqRuleComment + ` -d 192.168.0.0/16 -j RETURN
-A ` + string(*defaultCfg.MasqChain) + ` ` + nonMasqRuleComment + ` -d 100.64.0.0/10 -j RETURN
-A ` + string(*defaultCfg.MasqChain) + ` ` + nonMasqRuleComment + ` -d 192.0.0.0/24 -j RETURN
-A ` + string(*defaultCfg.MasqChain) + ` ` + nonMasqRuleComment + ` -d 192.0.2.0/24 -j RETURN
-A ` + string(*defaultCfg.MasqChain) + ` ` + nonMasqRuleComment + ` -d 192.88.99.0/24 -j RETURN
-A ` + string(*defaultCfg.MasqChain) + ` ` + nonMasqRuleComment + ` -d 198.18.0.0/15 -j RETURN
-A ` + string(*defaultCfg.MasqChain) + ` ` + nonMasqRuleComment + ` -d 198.51.100.0/24 -j RETURN
-A ` + string(*defaultCfg.MasqChain) + ` ` + nonMasqRuleComment + ` -d 203.0.113.0/24 -j RETURN
-A ` + string(*defaultCfg.MasqChain) + ` ` + nonMasqRuleComment + ` -d 240.0.0.0/4 -j RETURN
-A ` + string(*defaultCfg.MasqChain) + ` ` + masqRuleComment + ` -j MASQUERADE
COMMIT
`,
		},
		{
			desc: "config has ipv4 and ipv6 non masquerade cidr",
			cfg: &MasqConfig{
				NonMasqueradeCIDRs: strArrayPtr([]string{
					"10.244.0.0/16",
					"fc00::/7",
				}),
			},
			want: `*nat
:` + string(utiliptables.ChainPostrouting) + ` - [0:0]
:` + string(*defaultCfg.MasqChain) + ` - [0:0]
-A ` + string(utiliptables.ChainPostrouting) + ` -m comment --comment ` +
				fmt.Sprintf(postRoutingMasqChainCommentFormat, *defaultCfg.MasqChain) + ` -m addrtype ! --dst-type LOCAL -j ` + string(*defaultCfg.MasqChain) + `
-A ` + string(*defaultCfg.MasqChain) + ` ` + nonMasqRuleComment + ` -d 169.254.0.0/16 -j RETURN
-A ` + string(*defaultCfg.MasqChain) + ` ` + nonMasqRuleComment + ` -d 10.244.0.0/16 -j RETURN
-A ` + string(*defaultCfg.MasqChain) + ` ` + masqRuleComment + ` -j MASQUERADE
COMMIT
`,
		},
	})
}

// tests MasqDaemon.syncMasqRules
func TestSyncMasqRules(t *testing.T) {

	for _, tt := range generateSyncMasqRulesTests() {
		t.Run(tt.desc, func(t *testing.T) {
			m := NewFakeMasqDaemon()
			m.config = NewMasqConfig(*tt.cfg)
			m.syncMasqRules()
			fipt, ok := m.iptables.(*iptest.FakeIPTables)
			if !ok {
				t.Errorf("MasqDaemon wasn't using the expected iptables mock")
			}
			ttdump, err := iptest.ParseIPTablesDump(tt.want)
			if err != nil {
				t.Error(err)
			}
			ttchain, err := ttdump.GetChain(iptables.TableNAT, iptables.Chain(*m.config.MasqChain))
			if err != nil {
				t.Error(err)
			}
			chain, err := fipt.Dump.GetChain(iptables.TableNAT, iptables.Chain(*m.config.MasqChain))
			if err != nil {
				t.Error(err)
			}
			if len(ttchain.Rules) != len(chain.Rules) {
				t.Errorf("syncMasqRules wrote %d rules, want %d", len(chain.Rules), len(ttchain.Rules))
			}
			for i, rule := range chain.Rules {
				if rule.Raw != ttchain.Rules[i].Raw {
					t.Errorf("syncMasqRules wrote %q, want %q", rule.Raw, ttchain.Rules[i].Raw)
				}
			}
		})
	}
}

func generateRulesIPv6() []testMasqRule {
	defaultCfg := NewMasqConfig(MasqConfig{})
	return appendRulesOutput(true, []testMasqRule{
		{
			desc: "empty config",
			cfg: &MasqConfig{
				EnableIPv6:         true,
				NonMasqueradeCIDRs: strArrayPtr([]string{}),
			},
			want: `*nat
:` + string(utiliptables.ChainPrerouting) + ` - [0:0]
:` + string(utiliptables.ChainInput) + ` - [0:0]
:` + string(utiliptables.ChainOutput) + ` - [0:0]
:` + string(utiliptables.ChainPostrouting) + ` - [0:0]
:` + string(*defaultCfg.MasqChain) + ` - [0:0]
-A ` + string(utiliptables.ChainPostrouting) + ` -m comment --comment ` +
				fmt.Sprintf(postRoutingMasqChainCommentFormat, *defaultCfg.MasqChain) + ` -m addrtype ! --dst-type LOCAL -j ` + string(*defaultCfg.MasqChain) + `
-A ` + string(*defaultCfg.MasqChain) + ` ` + nonMasqRuleComment + ` -d fe80::/10 -j RETURN
-A ` + string(*defaultCfg.MasqChain) + ` ` + masqRuleComment + ` -j MASQUERADE
COMMIT
`,
		},
		{
			desc: "config has ipv4 and ipv6 non masquerade cidr",
			cfg: &MasqConfig{
				EnableIPv6: true,
				NonMasqueradeCIDRs: strArrayPtr([]string{
					"10.244.0.0/16",
					"fc00::/7",
				}),
			},
			want: `*nat
:` + string(utiliptables.ChainPrerouting) + ` - [0:0]
:` + string(utiliptables.ChainInput) + ` - [0:0]
:` + string(utiliptables.ChainOutput) + ` - [0:0]
:` + string(utiliptables.ChainPostrouting) + ` - [0:0]
:` + string(*defaultCfg.MasqChain) + ` - [0:0]
-A ` + string(utiliptables.ChainPostrouting) + ` -m comment --comment ` +
				fmt.Sprintf(postRoutingMasqChainCommentFormat, *defaultCfg.MasqChain) + ` -m addrtype ! --dst-type LOCAL -j ` + string(*defaultCfg.MasqChain) + `
-A ` + string(*defaultCfg.MasqChain) + ` ` + nonMasqRuleComment + ` -d fe80::/10 -j RETURN
-A ` + string(*defaultCfg.MasqChain) + ` ` + nonMasqRuleComment + ` -d fc00::/7 -j RETURN
-A ` + string(*defaultCfg.MasqChain) + ` ` + masqRuleComment + ` -j MASQUERADE
COMMIT
`,
		},
		{
			desc: "config has masqLinkLocalIPv6: false",
			cfg: &MasqConfig{
				EnableIPv6:         true,
				NonMasqueradeCIDRs: strArrayPtr([]string{}),
				MasqLinkLocalIPv6:  boolPtr(false),
			},
			want: `*nat
:` + string(utiliptables.ChainPrerouting) + ` - [0:0]
:` + string(utiliptables.ChainInput) + ` - [0:0]
:` + string(utiliptables.ChainOutput) + ` - [0:0]
:` + string(utiliptables.ChainPostrouting) + ` - [0:0]
:` + string(*defaultCfg.MasqChain) + ` - [0:0]
-A ` + string(utiliptables.ChainPostrouting) + ` -m comment --comment ` +
				fmt.Sprintf(postRoutingMasqChainCommentFormat, *defaultCfg.MasqChain) + ` -m addrtype ! --dst-type LOCAL -j ` + string(*defaultCfg.MasqChain) + `
-A ` + string(*defaultCfg.MasqChain) + ` ` + masqRuleComment + ` -j MASQUERADE
COMMIT
`,
		},
	})
}

func TestSyncRandomFullyMasq(t *testing.T) {
	m := NewFakeMasqDaemon()
	m.config = NewMasqConfig(MasqConfig{
		EnableIPv6:      true,
		MasqRandomFully: true,
	})
	err := m.syncMasqRules()
	if err != nil {
		t.Error(err)
	}

	fipt4, ok := m.iptables.(*iptest.FakeIPTables)
	if !ok {
		t.Errorf("MasqDaemon wasn't using the expected iptables mock")
	}
	buf := bytes.NewBuffer(nil)
	fipt4.SaveInto("nat", buf)
	bufStr := string(buf.Bytes())
	ipv4Want := `*nat
:PREROUTING - [0:0]
:INPUT - [0:0]
:OUTPUT - [0:0]
:POSTROUTING - [0:0]
:IP-MASQ-AGENT - [0:0]
-A POSTROUTING -m comment --comment "ip-masq-agent: ensure nat POSTROUTING directs all non-LOCAL destination traffic to our custom IP-MASQ-AGENT chain" -m addrtype ! --dst-type LOCAL -j IP-MASQ-AGENT
-A IP-MASQ-AGENT -m comment --comment "ip-masq-agent: local traffic is not subject to MASQUERADE" -d 169.254.0.0/16 -j RETURN
-A IP-MASQ-AGENT -m comment --comment "ip-masq-agent: local traffic is not subject to MASQUERADE" -d 10.0.0.0/8 -j RETURN
-A IP-MASQ-AGENT -m comment --comment "ip-masq-agent: local traffic is not subject to MASQUERADE" -d 172.16.0.0/12 -j RETURN
-A IP-MASQ-AGENT -m comment --comment "ip-masq-agent: local traffic is not subject to MASQUERADE" -d 192.168.0.0/16 -j RETURN
-A IP-MASQ-AGENT -m comment --comment "ip-masq-agent: outbound traffic is subject to MASQUERADE (must be last in chain)" -j MASQUERADE --random-fully
COMMIT
`
	if bufStr != ipv4Want {
		t.Errorf("syncMasqRulesIPv6 wrote %q, want %q", bufStr, ipv4Want)
	}

	err = m.syncMasqRulesIPv6()
	if err != nil {
		t.Error(err)
	}

	fipt6, ok := m.ip6tables.(*iptest.FakeIPTables)
	if !ok {
		t.Errorf("MasqDaemon wasn't using the expected iptables mock")
	}
	buf = bytes.NewBuffer(nil)
	fipt6.SaveInto("nat", buf)
	bufStr = string(buf.Bytes())
	ipv6Want := `*nat
:PREROUTING - [0:0]
:INPUT - [0:0]
:OUTPUT - [0:0]
:POSTROUTING - [0:0]
:IP-MASQ-AGENT - [0:0]
-A POSTROUTING -m comment --comment "ip-masq-agent: ensure nat POSTROUTING directs all non-LOCAL destination traffic to our custom IP-MASQ-AGENT chain" -m addrtype ! --dst-type LOCAL -j IP-MASQ-AGENT
-A IP-MASQ-AGENT -m comment --comment "ip-masq-agent: local traffic is not subject to MASQUERADE" -d fe80::/10 -j RETURN
-A IP-MASQ-AGENT -m comment --comment "ip-masq-agent: outbound traffic is subject to MASQUERADE (must be last in chain)" -j MASQUERADE --random-fully
COMMIT
`
	if bufStr != ipv6Want {
		t.Errorf("syncMasqRulesIPv6 wrote %q, want %q", bufStr, ipv6Want)
	}
}

// tests MasqDaemon.syncMasqRulesIPv6
func TestSyncMasqRulesIPv6(t *testing.T) {
	for _, tt := range generateRulesIPv6() {
		t.Run(tt.desc, func(t *testing.T) {
			m := NewFakeMasqDaemon()
			m.config = NewMasqConfig(*tt.cfg)
			m.config.EnableIPv6 = true
			err := m.syncMasqRulesIPv6()
			if err != nil {
				t.Error(err)
			}
			fipt6, ok := m.ip6tables.(*iptest.FakeIPTables)
			if !ok {
				t.Errorf("MasqDaemon wasn't using the expected iptables mock")
			}
			buf := bytes.NewBuffer(nil)
			fipt6.SaveInto("nat", buf)
			bufStr := string(buf.Bytes())
			if bufStr != tt.want {
				t.Errorf("syncMasqRulesIPv6 wrote %q, want %q", bufStr, tt.want)
			}
			ttdump, err := iptest.ParseIPTablesDump(tt.want)
			if err != nil {
				t.Error(err)
			}
			ttchain, err := ttdump.GetChain(iptables.TableNAT, iptables.Chain(*m.config.MasqChain))
			if err != nil {
				t.Error(err)
			}
			chain, err := fipt6.Dump.GetChain(iptables.TableNAT, iptables.Chain(*m.config.MasqChain))
			if err != nil {
				t.Error(err)
			}
			if len(ttchain.Rules) != len(chain.Rules) {
				t.Errorf("syncMasqRules wrote %d rules, want %d", len(chain.Rules), len(ttchain.Rules))
			}
			for i, rule := range chain.Rules {
				if rule.Raw != ttchain.Rules[i].Raw {
					t.Errorf("syncMasqRules wrote %q, want %q", rule.Raw, ttchain.Rules[i].Raw)
				}
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
	defaultCfg := NewMasqConfig(MasqConfig{})
	var writeNonMasqRuleTests = []struct {
		desc string
		cidr string
		want string
	}{
		{
			desc: "with ipv4 non masquerade cidr",
			cidr: "10.0.0.0/8",
			want: string(utiliptables.Append) + " " + string(*defaultCfg.MasqChain) +
				` -m comment --comment "ip-masq-agent: local traffic is not subject to MASQUERADE"` +
				" -d 10.0.0.0/8 -j RETURN\n",
		},
		{
			desc: "with ipv6 non masquerade cidr",
			cidr: "fc00::/7",
			want: string(utiliptables.Append) + " " + string(*defaultCfg.MasqChain) +
				` -m comment --comment "ip-masq-agent: local traffic is not subject to MASQUERADE"` +
				" -d fc00::/7 -j RETURN\n",
		},
	}

	for _, tt := range writeNonMasqRuleTests {
		t.Run(tt.desc, func(t *testing.T) {
			lines := bytes.NewBuffer(nil)
			defaultCfg.writeNonMasqRule(lines, tt.cidr, nil)

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
	defaultCfg := NewMasqConfig(MasqConfig{})
	lines := bytes.NewBuffer(nil)
	want := string(utiliptables.Append) + " " + string(*defaultCfg.MasqChain) +
		" -m comment --comment \"test writing a rule\"\n"
	writeRule(lines, utiliptables.Append, *defaultCfg.MasqChain, "-m", "comment", "--comment", `"test writing a rule"`)

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
