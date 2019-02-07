package config

import (
	"context"
	"fmt"
	"io/ioutil"
	"strings"
	"sync"
	"time"

	"github.com/matryer/runner"
	log "github.com/sirupsen/logrus"
	yaml "gopkg.in/yaml.v2"

	"github.com/prometheus/common/config"
	"github.com/prometheus/common/model"
	"github.com/prometheus/common/promlog"
	"github.com/prometheus/prometheus/discovery/marathon"
	"github.com/prometheus/prometheus/discovery/targetgroup"
)

const (
	taskRefresh = 45
	taskTimeout = 60
)

type Config struct {
	AutoTargets       map[string]AutoTarget  `yaml:"autotargets"`
	DiscoveryManagers map[string]interface{} `yaml:"-"`
	Includes          []string               `yaml:"include"`
	Modules           map[string]Module      `yaml:"modules"`
	Targets           []string               `yaml:"targets"`
	SourceHost        string                 `yaml:"source_host"`
	targets           map[string]bool        `yaml:"-"`
}

type SafeConfig struct {
	sync.RWMutex
	C     *Config
	tasks []Task
}

type Task struct {
	Name   string
	Runner *runner.Task
}

func (s *SafeConfig) ReloadConfig(cfg string) error {
	var c = &Config{}
	var targets map[string]bool

	yamlFile, err := ioutil.ReadFile(cfg)
	if err != nil {
		return fmt.Errorf("Error reading config file: %s", err)
	}

	if err := yaml.UnmarshalStrict(yamlFile, c); err != nil {
		return fmt.Errorf("Error parsing config file: %s", err)
	}

	targets = make(map[string]bool)
	for _, include := range c.Includes {
		yamlFile, err := ioutil.ReadFile(include)
		if err != nil {
			log.Errorf("Could not read included config file: %s. Ignoring...", err)
			continue
		}
		includeC := &Config{}
		if err := yaml.UnmarshalStrict(yamlFile, includeC); err != nil {
			log.Errorf("Could not parse included config file: %s. Ignoring...", err)
			continue
		}
		for _, target := range includeC.Targets {
			c.Targets = append(c.Targets, target)
			targets[target] = true
		}
	}
	// all this stuff from here -->
	c.DiscoveryManagers = make(map[string]interface{})
	for key := range c.AutoTargets {
		if strings.ToLower(key) == "dcos" {
			atConfig := c.AutoTargets[key]

			sdConfig := marathon.SDConfig{Servers: atConfig.Servers,
				RefreshInterval:  atConfig.RefreshInterval,
				HTTPClientConfig: atConfig.HTTPClientConfig}
			promlogLevel := &promlog.AllowedLevel{}
			promlogLevel.Set("debug")
			promlogFormat := &promlog.AllowedFormat{}
			promlogFormat.Set("logfmt")
			promlogConfig := &promlog.Config{Level: promlogLevel,
				Format: promlogFormat}
			logger := promlog.New(promlogConfig)
			discovery, err := marathon.NewDiscovery(sdConfig, logger)
			if err != nil {
				log.Errorf("Could not start discovery process for %v method. skipping...", key)
				continue
			}
			c.DiscoveryManagers[key] = discovery
		} else {
			log.Warnf("Unknown discovery method %v. skipping...", key)
		}
		// to here, needs to be re-thought out.
	}
	for _, target := range c.Targets {
		targets[target] = true
	}

	s.Lock()
	c.targets = targets
	s.C = c
	s.Unlock()
	return nil
}

func (c *Config) GetTargets() map[string]bool {
	return c.targets
}

func (c *Config) SetTargets(targets map[string]bool) {
	c.targets = targets
}

func (s *SafeConfig) UpdateTargets(t map[string]bool) {
	s.Lock()
	targets := s.C.GetTargets()
	for k := range t {
		targets[k] = true
	}
	s.C.SetTargets(targets)
	s.Unlock()
}

func (s *SafeConfig) DeleteTargets(t map[string]bool) {
	s.Lock()
	targets := s.C.GetTargets()
	for k := range t {
		delete(targets, k)
	}
	s.C.SetTargets(targets)
	s.Unlock()
}

func (s *SafeConfig) StartAutoDiscoverers() {
	log.Debugf("SafeConfig::StartAutoDiscoverers(): starting autodiscovery processes.")
	for manager := range s.C.DiscoveryManagers {
		switch manager {
		case "dcos":
			log.Debugf("SafeConfig::StartAutoDiscoverers(): starting %s discovery.", manager)
			task := runner.Go(func(stopDiscoverer runner.S) error {
				var (
					ctx          context.Context
					cancel       context.CancelFunc
					targetGroups []*targetgroup.Group
					ts           chan []*targetgroup.Group
				)
				d := s.C.DiscoveryManagers[manager]

				// work to do at the end after break.
				defer func() {
					cancel()
					mapTargets := make(map[string]bool)
					mgr := s.C.AutoTargets[manager]
					for _, v := range mgr.Targets {
						mapTargets[v] = true
					}
					s.DeleteTargets(mapTargets)
					mgr.Targets = []string{}
					s.C.AutoTargets[manager] = mgr
				}()

				for {
					if stopDiscoverer() {
						break
					}
					switch manager {
					case "dcos":
						log.Debugf("Autodiscovery: starting marathon dragnet app discovery")
						ctx = context.Background()
						ctx, cancel = context.WithCancel(ctx)
						ts = make(chan []*targetgroup.Group)
						discovery := d.(*marathon.Discovery)
						go discovery.Run(ctx, ts)
						select {
						case <-ts:
							targetGroups = <-ts
							cancel()
							break
						case <-time.After(taskTimeout * time.Second):
							continue

						}
						newTargets := make(map[string]bool)
						var listTargets []string
						atConfig := s.C.AutoTargets[manager]
						for _, target := range targetGroups {
							if atConfig.ServiceName == target.Source {
								for _, label := range target.Targets {
									newTargets[string(label["__address__"])] = true
									listTargets = append(listTargets, string(label["__address__"]))
								}
							}
						}
						// stegen - will do something better here someday, maybe.
						mgr := s.C.AutoTargets[manager]
						mgr.Targets = listTargets
						s.C.AutoTargets[manager] = mgr
						s.UpdateTargets(newTargets)
					default:
						// this shouldn't get hit
						return nil
					}
					if stopDiscoverer() {
						break
					}
					time.Sleep(taskRefresh * time.Second)
				}
				return nil
			})
			s.tasks = append(s.tasks, Task{Name: manager, Runner: task})
		default:
			// this is not a valid manager at the time
			return
		}
	}
	log.Debugf("SafeConfig::StartAutoDiscoverers(): started autodiscovery processes.")
}

func (s *SafeConfig) StopAutoDiscoverers() error {
	log.Debugf("SafeConfig::StopAutoDiscoverers(): stopping autodiscovery processes.")
	for _, t := range s.tasks {
		task := t.Runner
		log.Debugf("SafeConfig::StopAutoDiscoverers(): stopping %v discovery.", t.Name)
		log.Debugf("SafeConfig::StopAutoDiscoverers(): task=%#v", task)
		task.Stop()
		log.Debugf("SafeConfig::StopAutoDiscoverers(): task=%#v", task)
		select {
		case <-task.StopChan():
			log.Debugf("SafeConfig::StopAutoDiscoverers(): stopped %v discovery.", t.Name)
		case <-time.After(taskTimeout * time.Second):
			log.Errorf("SafeConfig::StopAutoDiscoverers(): failed to stop %v discovery in time.", t.Name)
		}
		if task.Err() != nil {
			log.Errorf("SafeConfig::StopAutoDiscoverers(): failed to stop %v discovery!", t.Name)
		}

	}
	log.Debugf("SafeConfig::StopAutoDiscoverers(): stopped autodiscovery processes.")
	return nil
}

type AutoTarget struct {
	Servers          []string                `yaml:"servers,omitempty"`
	ServiceName      string                  `yaml:"service_name"`
	RefreshInterval  model.Duration          `yaml:"refresh_interval,omitempty"`
	AuthToken        config.Secret           `yaml:"auth_token"`
	HTTPClientConfig config.HTTPClientConfig `yaml:",inline"`
	Targets          []string                `yaml:"targets"`
}

type Module struct {
	Size    int           `yaml:"size,omitempty"`
	Prober  string        `yaml:"prober,omitempty"`
	Timeout time.Duration `yaml:"timeout,omitempty"`
	HTTP    HTTPProbe     `yaml:"http,omitempty"`
	TCP     TCPProbe      `yaml:"tcp,omitempty"`
	ICMP    ICMPProbe     `yaml:"icmp,omitempty"`
	DNS     DNSProbe      `yaml:"dns,omitempty"`
}

type QueryResponse struct {
	Expect   string `yaml:"expect,omitempty"`
	Send     string `yaml:"send,omitempty"`
	StartTLS bool   `yaml:"starttls,omitempty"`
}

type HTTPProbe struct {
	// Defaults to 2xx.
	ValidStatusCodes       []int                   `yaml:"valid_status_codes,omitempty"`
	ValidHTTPVersions      []string                `yaml:"valid_http_versions,omitempty"`
	IPProtocol             string                  `yaml:"preferred_ip_protocol,omitempty"`
	IPProtocolFallback     bool                    `yaml:"ip_protocol_fallback,omitempty"`
	NoFollowRedirects      bool                    `yaml:"no_follow_redirects,omitempty"`
	FailIfSSL              bool                    `yaml:"fail_if_ssl,omitempty"`
	FailIfNotSSL           bool                    `yaml:"fail_if_not_ssl,omitempty"`
	Method                 string                  `yaml:"method,omitempty"`
	Headers                map[string]string       `yaml:"headers,omitempty"`
	FailIfMatchesRegexp    []string                `yaml:"fail_if_matches_regexp,omitempty"`
	FailIfNotMatchesRegexp []string                `yaml:"fail_if_not_matches_regexp,omitempty"`
	Body                   string                  `yaml:"body,omitempty"`
	HTTPClientConfig       config.HTTPClientConfig `yaml:"http_client_config,inline"`
}

type TCPProbe struct {
	IPProtocol         string           `yaml:"preferred_ip_protocol,omitempty"`
	IPProtocolFallback bool             `yaml:"ip_protocol_fallback,omitempty"`
	SourceIPAddress    string           `yaml:"source_ip_address,omitempty"`
	QueryResponse      []QueryResponse  `yaml:"query_response,omitempty"`
	TLS                bool             `yaml:"tls,omitempty"`
	TLSConfig          config.TLSConfig `yaml:"tls_config,omitempty"`
}

type ICMPProbe struct {
	IPProtocol         string `yaml:"preferred_ip_protocol,omitempty"` // Defaults to "ip6".
	IPProtocolFallback bool   `yaml:"ip_protocol_fallback,omitempty"`
	SourceIPAddress    string `yaml:"source_ip_address,omitempty"`
	PayloadSize        int    `yaml:"payload_size,omitempty"`
	DontFragment       bool   `yaml:"dont_fragment,omitempty"`
}

type DNSProbe struct {
	IPProtocol         string         `yaml:"preferred_ip_protocol,omitempty"`
	IPProtocolFallback bool           `yaml:"ip_protocol_fallback,omitempty"`
	SourceIPAddress    string         `yaml:"source_ip_address,omitempty"`
	TransportProtocol  string         `yaml:"transport_protocol,omitempty"`
	QueryName          string         `yaml:"query_name,omitempty"`
	QueryType          string         `yaml:"query_type,omitempty"`   // Defaults to ANY.
	ValidRcodes        []string       `yaml:"valid_rcodes,omitempty"` // Defaults to NOERROR.
	ValidateAnswer     DNSRRValidator `yaml:"validate_answer_rrs,omitempty"`
	ValidateAuthority  DNSRRValidator `yaml:"validate_authority_rrs,omitempty"`
	ValidateAdditional DNSRRValidator `yaml:"validate_additional_rrs,omitempty"`
}

type DNSRRValidator struct {
	FailIfMatchesRegexp    []string `yaml:"fail_if_matches_regexp,omitempty"`
	FailIfNotMatchesRegexp []string `yaml:"fail_if_not_matches_regexp,omitempty"`
}
