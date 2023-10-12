/*
Copyright 2017 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
	"k8s.io/component-base/logs"
	"k8s.io/component-base/version/verflag"
	"k8s.io/ip-masq-agent/cmd/ip-masq-agent/testing/fakefs"
	"k8s.io/ip-masq-agent/pkg/version"
	utiliptables "k8s.io/kubernetes/pkg/util/iptables"
	utilexec "k8s.io/utils/exec"

	"github.com/golang/glog"
)

const (
	linkLocalCIDR = "169.254.0.0/16"
	// RFC 4291
	linkLocalCIDRIPv6 = "fe80::/10"
	// path to a yaml or json file
	configPath = "/etc/config/ip-masq-agent"
)

// MasqConfig object
type MasqConfig struct {
	NonMasqueradeCIDRs     *[]string `json:"nonMasqueradeCIDRs,omitempty" yaml:"nonMasqueradeCIDRs,omitempty"`
	CidrLimit              int       `json:"cidrLimit" yaml:"cidrLimit"`
	MasqLinkLocal          *bool     `json:"masqLinkLocal,omitempty" yaml:"masqLinkLocal,omitempty"`
	MasqLinkLocalIPv6      *bool     `json:"masqLinkLocalIPv6,omitempty" yaml:"masqLinkLocalIPv6,omitempty"`
	OptionalResyncInterval *Duration `json:"resyncInterval,omitempty" yaml:"resyncInterval,omitempty"`
	OutputInterface        *string   `json:"outputInterface,omitempty" yaml:"outputInterface,omitempty"`
	// OutputAddress:
	// 1. IP address (IPv4 or IPv6)
	// 2. IP ranges (CIDR notation)
	// 3. IP ranges (start-end notation)
	// and port ranges (start-end notation)
	// https://www.netfilter.org/documentation/HOWTO/NAT-HOWTO-6.html#ss6.1
	OutputAddress               *string             `json:"outputAddress,omitempty" yaml:"outputAddress,omitempty"`
	OutputAddressIPv6           *string             `json:"outputAddressIPv6,omitempty" yaml:"outputAddressIPv6,omitempty"`
	MasqChain                   *utiliptables.Chain `json:"masqChain,omitempty" yaml:"masqChain,omitempty"`
	MasqRandomFully             bool                `json:"masqRandomFully,omitempty" yaml:"masqRandomFully,omitempty"`
	MasqueradeAllReservedRanges bool                `json:"masqAllReservedRanges,omitempty" yaml:"masqAllReservedRanges,omitempty"`
	EnableIPv6                  bool                `json:"enableIPv6,omitempty" yaml:"enableIPv6,omitempty"`
}

func boolPtr(b bool) *bool {
	return &b
}

// Duration - Go's JSON unmarshaler can't handle time.ParseDuration syntax when unmarshaling into time.Duration, so we do it here
type Duration time.Duration

// UnmarshalJSON ...
func (d *Duration) UnmarshalJSON(json []byte) error {
	if json[0] == '"' {
		s := string(json[1 : len(json)-1])
		t, err := time.ParseDuration(s)
		if err != nil {
			return err
		}
		*d = Duration(t)
		return nil
	}
	s := string(json)
	return fmt.Errorf("expected string value for unmarshal to field of type Duration, got %q", s)
}

func (d *Duration) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var s string
	if err := unmarshal(&s); err != nil {
		return err
	}
	t, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	*d = Duration(t)
	return nil
}

func (d Duration) MarshalYAML() (interface{}, error) {
	node := yaml.Node{
		Kind:  yaml.ScalarNode,
		Style: yaml.SingleQuotedStyle,
		Value: time.Duration(d).String(),
	}
	return node, nil
}

func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

const defaultDuration = Duration(60 * time.Second)

func (mc MasqConfig) ResyncInterval() time.Duration {
	out := time.Duration(defaultDuration)
	if mc.OptionalResyncInterval != nil {
		out = time.Duration(*mc.OptionalResyncInterval)
		if out.Nanoseconds() == 0 {
			out = time.Duration(defaultDuration)
		}
	}
	return out
}

// NewMasqConfig returns a MasqConfig with default values
func NewMasqConfig(mc MasqConfig) *MasqConfig {
	myDuration := defaultDuration
	masqChain := utiliptables.Chain("IP-MASQ-AGENT")
	ret := MasqConfig{
		NonMasqueradeCIDRs:          nil,
		CidrLimit:                   64,
		MasqLinkLocal:               boolPtr(true),
		MasqLinkLocalIPv6:           nil, // inherit from EnableIPv6
		OptionalResyncInterval:      &myDuration,
		OutputInterface:             nil,
		OutputAddress:               nil,
		OutputAddressIPv6:           nil,
		MasqChain:                   &masqChain,
		MasqRandomFully:             false,
		MasqueradeAllReservedRanges: false,
		EnableIPv6:                  false,
	}

	ret.EnableIPv6 = mc.EnableIPv6
	ret.NonMasqueradeCIDRs = mc.NonMasqueradeCIDRs

	if mc.CidrLimit > 0 {
		ret.CidrLimit = mc.CidrLimit
	}
	if mc.MasqLinkLocal != nil {
		ret.MasqLinkLocal = mc.MasqLinkLocal
	}
	if !ret.EnableIPv6 {
		ret.MasqLinkLocalIPv6 = boolPtr(false)
	} else if mc.MasqLinkLocalIPv6 != nil {
		ret.MasqLinkLocalIPv6 = mc.MasqLinkLocalIPv6
	}
	if mc.OptionalResyncInterval != nil {
		ret.OptionalResyncInterval = mc.OptionalResyncInterval
	}
	if mc.OutputInterface != nil {
		ret.OutputInterface = mc.OutputInterface
	}
	if mc.OutputAddress != nil {
		ret.OutputAddress = mc.OutputAddress
	}
	if mc.OutputAddressIPv6 != nil {
		ret.OutputAddressIPv6 = mc.OutputAddressIPv6
	}
	if mc.MasqChain != nil && *mc.MasqChain != "" {
		ret.MasqChain = mc.MasqChain
	}
	ret.MasqRandomFully = mc.MasqRandomFully
	ret.MasqueradeAllReservedRanges = mc.MasqueradeAllReservedRanges
	return &ret
}

// MasqDaemon object
type MasqDaemon struct {
	config    *MasqConfig
	iptables  utiliptables.Interface
	ip6tables utiliptables.Interface
}

// NewMasqDaemon returns a MasqDaemon with default values, including an initialized utiliptables.Interface
func NewMasqDaemon(c *MasqConfig) *MasqDaemon {
	execer := utilexec.New()
	protocolv4 := utiliptables.ProtocolIPv4
	protocolv6 := utiliptables.ProtocolIPv6
	iptables := utiliptables.New(execer, protocolv4)
	ip6tables := utiliptables.New(execer, protocolv6)
	return &MasqDaemon{
		config:    c,
		iptables:  iptables,
		ip6tables: ip6tables,
	}
}

type MsgConfigFlag struct {
	masqChain                     *string
	masqRandomFully               *bool
	noMasqueradeAllReservedRanges *bool
	enableIPv6                    *bool
}

func initMasqConfigFlag() MsgConfigFlag {
	return MsgConfigFlag{
		masqChain:                     flag.String("masq-chain", "IP-MASQ-AGENT", `Name of nat chain for iptables masquerade rules.`),
		masqRandomFully:               flag.Bool("masq-random-fully", false, "Whether to fully randomize the source port of masqueraded traffic."),
		noMasqueradeAllReservedRanges: flag.Bool("nomasq-all-reserved-ranges", false, "Whether to disable masquerade for all IPv4 ranges reserved by RFCs."),
		enableIPv6:                    flag.Bool("enable-ipv6", false, "Whether to enable IPv6."),
	}
}

func main() {
	mcf := initMasqConfigFlag()
	flag.Parse()

	glog.Infof("ip-masq-agent version: %s", version.Version)

	flag.CommandLine.VisitAll(func(f *flag.Flag) {
		glog.Infof("FLAG: --%s=%q", f.Name, f.Value)
	})

	masqChain := utiliptables.Chain(*mcf.masqChain)

	c := NewMasqConfig(MasqConfig{
		MasqueradeAllReservedRanges: !*mcf.noMasqueradeAllReservedRanges,
		MasqChain:                   &masqChain,
		MasqRandomFully:             *mcf.masqRandomFully,
		EnableIPv6:                  *mcf.enableIPv6,
	})

	logs.InitLogs()
	defer logs.FlushLogs()

	verflag.PrintAndExitIfRequested()

	m := NewMasqDaemon(c)
	m.Run()
}

// Run ...
func (m *MasqDaemon) Run() {
	// Periodically resync to reconfigure or heal from any rule decay
	for {
		func() {
			defer time.Sleep(m.config.ResyncInterval())
			// resync config
			if err := m.osSyncConfig(); err != nil {
				glog.Errorf("error syncing configuration: %v", err)
				return
			}
			// resync rules
			if err := m.syncMasqRules(); err != nil {
				glog.Errorf("error syncing masquerade rules: %v", err)
				return
			}
			// resync ipv6 rules
			if err := m.syncMasqRulesIPv6(); err != nil {
				glog.Errorf("error syncing masquerade rules for ipv6: %v", err)
				return
			}
		}()
	}
}

func (m *MasqDaemon) osSyncConfig() error {
	// the fakefs.FileSystem interface allows us to mock the fs from tests
	// fakefs.DefaultFS implements fakefs.FileSystem using os.Stat and io/ioutil.ReadFile
	var fs fakefs.FileSystem = fakefs.DefaultFS{}
	return m.syncConfig(fs)
}

// Syncs the config to the file at ConfigPath, or uses defaults if the file could not be found
// Error if the file is found but cannot be parsed.
func (m *MasqDaemon) syncConfig(fs fakefs.FileSystem) error {
	var err error
	c := NewMasqConfig(*m.config)
	defer func() {
		if err == nil {
			json, _ := json.Marshal(c)
			glog.V(2).Infof("using config: %s", string(json))
		}
	}()

	// check if file exists
	if _, err = fs.Stat(configPath); os.IsNotExist(err) {
		// file does not exist, use defaults
		m.config.NonMasqueradeCIDRs = c.NonMasqueradeCIDRs
		m.config.CidrLimit = c.CidrLimit
		m.config.MasqLinkLocal = c.MasqLinkLocal
		m.config.MasqLinkLocalIPv6 = c.MasqLinkLocalIPv6
		m.config.OptionalResyncInterval = c.OptionalResyncInterval
		m.config.OutputInterface = c.OutputInterface
		m.config.OutputAddress = c.OutputAddress
		m.config.OutputAddressIPv6 = c.OutputAddressIPv6
		m.config.MasqChain = c.MasqChain
		m.config.MasqueradeAllReservedRanges = c.MasqueradeAllReservedRanges
		m.config.EnableIPv6 = c.EnableIPv6
		glog.V(2).Infof("no config file found at %q, using default values", configPath)
		return nil
	}
	glog.V(2).Infof("config file found at %q", configPath)

	// file exists, read and parse file
	yamlOrJson, err := fs.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("error reading config file: %v", err)
	}

	err = yaml.Unmarshal(yamlOrJson, c)
	if err != nil {
		// Only overwrites fields provided in JSON
		if err = json.Unmarshal(yamlOrJson, c); err != nil {
			return fmt.Errorf("error unmarshal config file: %v:%s", err, string(yamlOrJson))
		}
	}
	// apply defaults*
	c = NewMasqConfig(*c)

	// validate configuration
	if err := c.validate(); err != nil {
		return fmt.Errorf("error validating config file: %v", err)
	}

	// apply new config
	m.config = c
	return nil
}

type IpAddrType string

const (
	V4   IpAddrType = "v4"
	V6   IpAddrType = "v6"
	BOTH IpAddrType = "v4v6"
)

func (mc *MasqConfig) DoNotMasqueradeCIDRs(ipType IpAddrType) []string {
	nonMasq := []string{}
	// link-local CIDR is always non-masquerade
	if *mc.MasqLinkLocal {
		nonMasq = append(nonMasq, linkLocalCIDR)
	}
	if mc.EnableIPv6 && (mc.MasqLinkLocalIPv6 == nil || *mc.MasqLinkLocalIPv6) {
		nonMasq = append(nonMasq, linkLocalCIDRIPv6)
	}
	if mc.NonMasqueradeCIDRs == nil {
		// RFC 1918 defines the private ip address space as 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
		nonMasq = append(nonMasq, "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
		if mc.MasqueradeAllReservedRanges {
			nonMasq = append(nonMasq,
				"100.64.0.0/10",   // RFC 6598
				"192.0.0.0/24",    // RFC 6890
				"192.0.2.0/24",    // RFC 5737
				"192.88.99.0/24",  // RFC 7526
				"198.18.0.0/15",   // RFC 6815
				"198.51.100.0/24", // RFC 5737
				"203.0.113.0/24",  // RFC 5737
				"240.0.0.0/4")     // RFC 5735, Former Class E range obsoleted by RFC 3232
		}
	} else {
		nonMasq = append(nonMasq, *mc.NonMasqueradeCIDRs...)
	}
	filtered := []string{}
	for _, cidr := range nonMasq {
		if ipType == V4 {
			if isIPv6CIDR(cidr) {
				continue
			}
			filtered = append(filtered, cidr)
		} else if ipType == V6 {
			if isIPv4CIDR(cidr) {
				continue
			}
			filtered = append(filtered, cidr)
		} else {
			filtered = append(filtered, cidr)
		}
	}
	return filtered
}

func (c *MasqConfig) validate() error {
	ityp := V4
	if c.EnableIPv6 {
		ityp = BOTH
	}
	nonCidrs := c.DoNotMasqueradeCIDRs(ityp)
	// limit to 64 CIDRs (excluding link-local) to protect against really bad mistakes
	n := len(nonCidrs)
	l := c.CidrLimit

	if n > l {
		return fmt.Errorf("the daemon can only accept up to %d CIDRs (excluding link-local), but got %d CIDRs (excluding link local)", l, n)
	}
	// check CIDRs are valid
	for _, cidr := range nonCidrs {
		if err := validateCIDR(cidr); err != nil {
			return err
		}
		// can't configure ipv6 cidr if ipv6 is not enabled
		if !c.EnableIPv6 && isIPv6CIDR(cidr) {
			return fmt.Errorf("ipv6 is not enabled, but ipv6 cidr %s provided. Enable ipv6 using --enable-ipv6 agent flag", cidr)
		}
	}
	return nil
}

const cidrParseErrFmt = "CIDR %q could not be parsed, %v"
const cidrAlignErrFmt = "CIDR %q is not aligned to a CIDR block, ip: %q network: %q"

func validateCIDR(cidr string) error {
	// parse test
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf(cidrParseErrFmt, cidr, err)
	}
	// alignment test
	if !ip.Equal(ipnet.IP) {
		return fmt.Errorf(cidrAlignErrFmt, cidr, ip, ipnet.String())
	}
	return nil
}

func (m *MasqDaemon) syncMasqRules() error {
	// make sure our custom chain for non-masquerade exists
	m.iptables.EnsureChain(utiliptables.TableNAT, *m.config.MasqChain)

	// ensure that any non-local in POSTROUTING jumps to masqChain
	if err := m.ensurePostroutingJump(); err != nil {
		return err
	}

	// build up lines to pass to iptables-restore
	lines := bytes.NewBuffer(nil)
	writeLine(lines, "*nat")
	writeLine(lines, utiliptables.MakeChainLine(*m.config.MasqChain)) // effectively flushes masqChain atomically with rule restore

	// non-masquerade for user-provided CIDRs
	for _, cidr := range m.config.DoNotMasqueradeCIDRs(V4) {
		m.config.writeNonMasqRule(lines, cidr, m.config.OutputAddress)
	}

	// masquerade all other traffic that is not bound for a --dst-type LOCAL destination
	m.config.writeMasqRuleIPv4(lines)

	writeLine(lines, "COMMIT")

	if err := m.iptables.RestoreAll(lines.Bytes(), utiliptables.NoFlushTables, utiliptables.NoRestoreCounters); err != nil {
		return fmt.Errorf("%v:%s", err, lines.String())
	}
	return nil
}

func (m *MasqDaemon) syncMasqRulesIPv6() error {
	isIPv6Enabled := m.config.EnableIPv6

	if isIPv6Enabled {
		// make sure our custom chain for ipv6 non-masquerade exists
		_, err := m.ip6tables.EnsureChain(utiliptables.TableNAT, *m.config.MasqChain)
		if err != nil {
			return err
		}
		// ensure that any non-local in POSTROUTING jumps to masqChain
		if err := m.ensurePostroutingJumpIPv6(); err != nil {
			return err
		}
		// build up lines to pass to ip6tables-restore
		lines6 := bytes.NewBuffer(nil)
		writeLine(lines6, "*nat")
		writeLine(lines6, utiliptables.MakeChainLine(*m.config.MasqChain)) // effectively flushes masqChain atomically with rule restore

		for _, cidr := range m.config.DoNotMasqueradeCIDRs(V6) {
			m.config.writeNonMasqRule(lines6, cidr, m.config.OutputAddressIPv6)
		}

		// masquerade all other traffic that is not bound for a --dst-type LOCAL destination
		m.config.writeMasqRuleIPv6(lines6)

		writeLine(lines6, "COMMIT")

		if err := m.ip6tables.RestoreAll(lines6.Bytes(), utiliptables.NoFlushTables, utiliptables.NoRestoreCounters); err != nil {
			return fmt.Errorf("%v:%s", err, lines6.String())
		}
	}
	return nil
}

// NOTE(mtaufen): iptables requires names to be <= 28 characters, and somehow prepending "-m comment --comment " to this string makes it think this condition is violated
// Feel free to dig around in iptables and see if you can figure out exactly why; I haven't had time to fully trace how it parses and handle subcommands.
// If you want to investigate, get the source via `git clone git://git.netfilter.org/iptables.git`, `git checkout v1.4.21` (the version I've seen this issue on,
// though it may also happen on others), and start with `git grep XT_EXTENSION_MAXNAMELEN`.
const postRoutingMasqChainCommentFormat = "\"ip-masq-agent: ensure nat POSTROUTING directs all non-LOCAL destination traffic to our custom %s chain\""

func (mc *MasqConfig) postroutingJumpComment() string {
	return fmt.Sprintf(postRoutingMasqChainCommentFormat, *mc.MasqChain)
}

func (m *MasqDaemon) ensurePostroutingJump() error {
	if _, err := m.iptables.EnsureRule(utiliptables.Append, utiliptables.TableNAT, utiliptables.ChainPostrouting,
		"-m", "comment", "--comment", m.config.postroutingJumpComment(),
		"-m", "addrtype", "!", "--dst-type", "LOCAL", "-j", string(*m.config.MasqChain)); err != nil {
		return fmt.Errorf("failed to ensure that %s chain %s jumps to MASQUERADE: %v", utiliptables.TableNAT, *m.config.MasqChain, err)
	}
	return nil
}

func (m *MasqDaemon) ensurePostroutingJumpIPv6() error {
	if _, err := m.ip6tables.EnsureRule(utiliptables.Append, utiliptables.TableNAT, utiliptables.ChainPostrouting,
		"-m", "comment", "--comment", m.config.postroutingJumpComment(),
		"-m", "addrtype", "!", "--dst-type", "LOCAL", "-j", string(*m.config.MasqChain)); err != nil {
		return fmt.Errorf("failed to ensure that %s chain %s jumps to MASQUERADE: %v for ipv6", utiliptables.TableNAT, *m.config.MasqChain, err)
	}
	return nil
}

const nonMasqRuleComment = `-m comment --comment "ip-masq-agent: local traffic is not subject to MASQUERADE"`
const nonSnatRuleComment = `-m comment --comment "ip-masq-agent: local traffic is not subject to SNAT"`

func (mc *MasqConfig) writeNonMasqRule(lines *bytes.Buffer, cidr string, outAddr *string) {
	if outAddr != nil {
		writeRule(lines, utiliptables.Append, *mc.MasqChain, nonSnatRuleComment, "-d", cidr, "-j", "RETURN")
	} else {
		writeRule(lines, utiliptables.Append, *mc.MasqChain, nonMasqRuleComment, "-d", cidr, "-j", "RETURN")
	}
}

const masqRuleComment = `-m comment --comment "ip-masq-agent: outbound traffic is subject to MASQUERADE (must be last in chain)"`
const snatRuleComment = `-m comment --comment "ip-masq-agent: outbound traffic is subject to SNAT (must be last in chain)"`

func (mc *MasqConfig) writeMasqRule(lines *bytes.Buffer, iface *string) {
	jMasquerade := []string{"-j", "MASQUERADE"}
	if mc.MasqRandomFully {
		jMasquerade = append(jMasquerade, "--random-fully")
	}
	if iface != nil {
		writeRule(lines, utiliptables.Append, *mc.MasqChain, append([]string{masqRuleComment, "-o", *iface}, jMasquerade...)...)
	} else {
		writeRule(lines, utiliptables.Append, *mc.MasqChain, append([]string{masqRuleComment}, jMasquerade...)...)
	}
}

func (mc *MasqConfig) writeMasqRuleIPv4(lines *bytes.Buffer) {
	if mc.OutputAddress != nil {
		writeRule(lines, utiliptables.Append, *mc.MasqChain, snatRuleComment, "-j", "SNAT", "--to-source", *mc.OutputAddress)
	} else {
		mc.writeMasqRule(lines, mc.OutputInterface)
	}
}

func (mc *MasqConfig) writeMasqRuleIPv6(lines *bytes.Buffer) {
	if mc.OutputAddressIPv6 != nil {
		writeRule(lines, utiliptables.Append, *mc.MasqChain, snatRuleComment, "-j", "SNAT", "--to-source", *mc.OutputAddressIPv6)
	} else {
		mc.writeMasqRule(lines, mc.OutputInterface)
	}
}

// Similar syntax to utiliptables.Interface.EnsureRule, except you don't pass a table
// (you must write these rules under the line with the table name)
func writeRule(lines *bytes.Buffer, position utiliptables.RulePosition, chain utiliptables.Chain, args ...string) {
	fullArgs := append([]string{string(position), string(chain)}, args...)
	writeLine(lines, fullArgs...)
}

// Join all words with spaces, terminate with newline and write to buf.
func writeLine(lines *bytes.Buffer, words ...string) {
	lines.WriteString(strings.Join(words, " ") + "\n")
}

// isIPv6CIDR checks if the provided cidr block belongs to ipv6 family.
// If cidr belongs to ipv6 family, return true else it returns false
// which means the cidr belongs to ipv4 family
func isIPv6CIDR(cidr string) bool {
	ip, _, _ := net.ParseCIDR(cidr)
	return isIPv6(ip.String())
}

func isIPv4CIDR(cidr string) bool {
	ip, _, _ := net.ParseCIDR(cidr)
	return isIPv4(ip.String())
}

// isIPv6 checks if the provided ip belongs to ipv6 family.
// If ip belongs to ipv6 family, return true else it returns false
// which means the ip belongs to ipv4 family
func isIPv6(ip string) bool {
	pip := net.ParseIP(ip)
	if pip == nil {
		return false
	}
	return pip.To4() == nil
}

func isIPv4(ip string) bool {
	pip := net.ParseIP(ip)
	if pip == nil {
		return false
	}
	return pip.To4() != nil
}
