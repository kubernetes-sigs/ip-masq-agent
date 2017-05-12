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
	utiljson "encoding/json"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
	"time"

	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/apiserver/pkg/util/logs"
	utildbus "k8s.io/kubernetes/pkg/util/dbus"
	utilexec "k8s.io/kubernetes/pkg/util/exec"
	utiliptables "k8s.io/kubernetes/pkg/util/iptables"
	"k8s.io/kubernetes/pkg/version/verflag"
	"k8s.io/non-masquerade-daemon/cmd/non-masquerade-daemon/testing/fakefs"

	"github.com/golang/glog"
)

const (
	// name of nat chain for iptables masquerade rules
	masqChain     = utiliptables.Chain("NON-MASQUERADE-DAEMON")
	linkLocalCIDR = "169.254.0.0/16"
	// path to a yaml or json file
	configPath = "/etc/config/non-masquerade-daemon"
)

// config object
type MasqConfig struct {
	NonMasqueradeCIDRs []string `json:"nonMasqueradeCIDRs"`
	LinkLocal          bool     `json:"linkLocal"`
	ResyncInterval     Duration `json:"resyncInterval"`
}

// Go's JSON unmarshaler can't handle time.ParseDuration syntax when unmarshaling into time.Duration, so we do it here
type Duration time.Duration

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

// reutrns a MasqConfig with default values
func NewMasqConfig() *MasqConfig {
	return &MasqConfig{
		// Note: RFC 1918 defines the private ip address space as 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
		NonMasqueradeCIDRs: []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"},
		LinkLocal:          true,
		ResyncInterval:     Duration(60 * time.Second),
	}
}

// daemon object
type MasqDaemon struct {
	config   *MasqConfig
	iptables utiliptables.Interface
}

// returns a MasqDaemon with default values, including an initialized utiliptables.Interface
func NewMasqDaemon(c *MasqConfig) *MasqDaemon {
	execer := utilexec.New()
	dbus := utildbus.New()
	protocol := utiliptables.ProtocolIpv4
	iptables := utiliptables.New(execer, dbus, protocol)
	return &MasqDaemon{
		config:   c,
		iptables: iptables,
	}
}

func main() {
	c := NewMasqConfig()

	logs.InitLogs()
	defer logs.FlushLogs()

	verflag.PrintAndExitIfRequested()

	m := NewMasqDaemon(c)
	if err := m.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}

func (m *MasqDaemon) Run() error {
	// sync to any config on disk
	if err := m.osSyncConfig(); err != nil {
		glog.Errorf("error syncing configuration: %v", err)
		return err
	}
	// initial setup
	if err := m.syncMasqRules(); err != nil {
		glog.Errorf("error syncing masquerade rules: %v", err)
		return err
	}
	// resync occasionally to reconfigure or heal from any rule decay
	for {
		select {
		case <-time.After(time.Duration(m.config.ResyncInterval)):
			// resync config
			if err := m.osSyncConfig(); err != nil {
				glog.Errorf("error syncing configuration: %v", err)
				return err
			}
			// resync rules
			if err := m.syncMasqRules(); err != nil {
				glog.Errorf("error syncing masquerade rules: %v", err)
				return err
			}
		}
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
	c := NewMasqConfig()
	defer func() {
		if err == nil {
			json, _ := utiljson.Marshal(c)
			glog.Infof("using config: %s", string(json))
		}
	}()

	// check if file exists
	if _, err = fs.Stat(configPath); os.IsNotExist(err) {
		// file does not exist, use defaults
		m.config.NonMasqueradeCIDRs = c.NonMasqueradeCIDRs
		m.config.LinkLocal = c.LinkLocal
		m.config.ResyncInterval = c.ResyncInterval
		glog.Infof("no config file found at %q", configPath)
		return nil
	}
	glog.Infof("config file found at %q", configPath)

	// file exists, read and parse file
	yaml, err := fs.ReadFile(configPath)
	if err != nil {
		return err
	}

	json, err := utilyaml.ToJSON(yaml)
	if err != nil {
		return err
	}

	// Only overwrites fields provided in JSON
	if err = utiljson.Unmarshal(json, c); err != nil {
		return err
	}

	// validate configuration
	if err := c.validate(); err != nil {
		return err
	}

	// apply new config
	m.config = c
	return nil
}

func (c *MasqConfig) validate() error {
	// limit to 64 CIDRs (excluding link-local) to protect against really bad mistakes
	n := len(c.NonMasqueradeCIDRs)
	if n > 64 {
		return fmt.Errorf("The daemon can only accept up to 64 CIDRs (excluding link-local), but got %d CIDRs (excluding link local).", n)
	}
	// check CIDRs are valid
	for _, cidr := range c.NonMasqueradeCIDRs {
		if err := validateCIDR(cidr); err != nil {
			return err
		}
	}
	return nil
}

const cidrRE = `^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$`
const cidrMatchErrFmt = "CIDR %q did not match %q (for example, '10.0.0.0/8' is correct CIDR notation)"
const cidrParseErrFmt = "CIDR %q could not be parsed, %v"
const cidrAlignErrFmt = "CIDR %q is not aligned to a CIDR block, ip: %q network: %q"

func validateCIDR(cidr string) error {
	// regex test
	re := regexp.MustCompile(cidrRE)
	if !re.MatchString(cidr) {
		return fmt.Errorf(cidrMatchErrFmt, cidr, cidrRE)
	}
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
	m.iptables.EnsureChain(utiliptables.TableNAT, masqChain)

	// ensure that any non-local in POSTROUTING jumps to masqChain
	if err := m.ensurePostroutingJump(); err != nil {
		return err
	}

	// build up lines to pass to iptables-restore
	lines := bytes.NewBuffer(nil)
	writeLine(lines, "*nat")
	writeLine(lines, utiliptables.MakeChainLine(masqChain)) // effectively flushes masqChain atomically with rule restore

	// link-local CIDR is always non-masquerade
	if m.config.LinkLocal {
		writeNonMasqRule(lines, linkLocalCIDR)
	}

	// non-masquerade for user-provided CIDRs
	for _, cidr := range m.config.NonMasqueradeCIDRs {
		writeNonMasqRule(lines, cidr)
	}

	// masquerade all other traffic that is not bound for a --dst-type LOCAL destination
	writeMasqRule(lines)

	writeLine(lines, "COMMIT")
	if err := m.iptables.RestoreAll(lines.Bytes(), utiliptables.NoFlushTables, utiliptables.NoRestoreCounters); err != nil {
		return err
	}
	return nil
}

// NOTE(mtaufen): iptables requires names to be <= 28 characters, and somehow prepending "-m comment --comment " to this string makes it think this condition is violated
// Feel free to dig around in iptables and see if you can figure out exactly why; I haven't had time to fully trace how it parses and handle subcommands.
// If you want to investigate, get the source via `git clone git://git.netfilter.org/iptables.git`, `git checkout v1.4.21` (the version I've seen this issue on,
// though it may also happen on others), and start with `git grep XT_EXTENSION_MAXNAMELEN`.
const postroutingJumpComment = "non-masquerade-daemon: ensure nat POSTROUTING directs all non-LOCAL destination traffic to our custom " + string(masqChain) + " chain"

func (m *MasqDaemon) ensurePostroutingJump() error {
	if _, err := m.iptables.EnsureRule(utiliptables.Append, utiliptables.TableNAT, utiliptables.ChainPostrouting,
		"-m", "comment", "--comment", postroutingJumpComment,
		// postroutingJumpComment,
		"-m", "addrtype", "!", "--dst-type", "LOCAL", "-j", string(masqChain)); err != nil {
		return fmt.Errorf("failed to ensure that %s chain %s jumps to MASQUERADE: %v", utiliptables.TableNAT, masqChain, err)
	}
	return nil
}

const nonMasqRuleComment = `-m comment --comment "non-masquerade-daemon: cluster-local traffic should not be subject to MASQUERADE"`

func writeNonMasqRule(lines *bytes.Buffer, cidr string) {
	writeRule(lines, utiliptables.Append, masqChain,
		nonMasqRuleComment,
		"-m", "addrtype", "!", "--dst-type", "LOCAL", "-d", cidr, "-j", "RETURN")
}

const masqRuleComment = `-m comment --comment "non-masquerade-daemon: outbound traffic should be subject to MASQUERADE (this match must come after cluster-local CIDR matches)"`

func writeMasqRule(lines *bytes.Buffer) {
	writeRule(lines, utiliptables.Append, masqChain,
		masqRuleComment,
		"-m", "addrtype", "!", "--dst-type", "LOCAL", "-j", "MASQUERADE")
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
