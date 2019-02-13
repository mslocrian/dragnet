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
	//"github.com/prometheus/common/model"
	"github.com/prometheus/common/promlog"
	"github.com/prometheus/prometheus/discovery/kubernetes"
	"github.com/prometheus/prometheus/discovery/marathon"
	"github.com/prometheus/prometheus/discovery/targetgroup"
)

const (
	taskRefresh = 45
	taskTimeout = 60
)

type Config struct {
	AutoTargets       map[string]interface{} `yaml:"autotargets"`
	DiscoveryManagers map[string]interface{} `yaml:"-"`
	Includes          []string               `yaml:"include,omitempty"`
	Modules           map[string]Module      `yaml:"modules"`
	Targets           []string               `yaml:"targets,omitempty"`
	SourceHost        string                 `yaml:"source_host,omitempty"`
	autoTargetsConfig map[string]*Target     `yaml:"-"`
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
	c.DiscoveryManagers = make(map[string]interface{})
	// all this stuff from here -->
	promlogLevel := &promlog.AllowedLevel{}
	promlogLevel.Set("debug")
	promlogFormat := &promlog.AllowedFormat{}
	promlogFormat.Set("logfmt")
	promlogConfig := &promlog.Config{Level: promlogLevel,
		Format: promlogFormat}
	logger := promlog.New(promlogConfig)
	// <-- to here needs to be rethought
	for key := range c.AutoTargets {
		switch strings.ToLower(key) {
		case "dcos", "mesosphere":
			sdConfig, err := getMarathonDiscoveryConfig(c.AutoTargets[key])
			if err != nil {
				log.Errorf("Could not parse discovery config for %s. err=%v. skipping...", key, err)
				break
			}
			c.SetAutoTargetConfig(key, sdConfig)
			discovery, err := marathon.NewDiscovery(sdConfig.GetConfig().(marathon.SDConfig), logger)
			if err != nil {
				log.Errorf("Could not start discovery process for %v method. err=%v. skipping...", key, err)
				break
			}
			c.DiscoveryManagers[key] = discovery
		case "kubernetes":
			sdConfig, err := getKubernetesDiscoveryConfig(c.AutoTargets[key])
			if err != nil {
				log.Errorf("Could not parse discovery config for %s. err=%v. skipping...", key, err)
				break
			}
			c.SetAutoTargetConfig(key, sdConfig)
			kConfig := sdConfig.GetConfig().(kubernetes.SDConfig)
			discovery, err := kubernetes.New(logger, &kConfig)
			//discovery, err := kubernetes.NewPod(logger, &kConfig)
			if err != nil {
				log.Errorf("Could not start discovery process for %v method. err=%v. skipping...", key, err)
				break
			}
			c.DiscoveryManagers[key] = discovery
		default:
			log.Warnf("Unknown discovery method %v. skipping...", key)
		}
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
	var resTargets map[string]bool
	resTargets = make(map[string]bool)
	for key := range c.AutoTargets {
		mgr := *c.GetAutoTargetConfig(key)
		for k, v := range mgr.GetTargets() {
			resTargets[k] = v
		}
	}

	// loop over static config targets
	for k, v := range c.targets {
		resTargets[k] = v
	}
	return resTargets
}

func (c *Config) SetTargets(targets map[string]bool) {
	c.targets = targets
}

func (c *Config) GetAutoTargetConfig(key string) *Target {
	if target, ok := c.autoTargetsConfig[key]; ok {
		return target
	} else {
		var res Target
		return &res
	}
}

func (c *Config) GetAutoTargets() map[string]*Target {
	return c.autoTargetsConfig
}

func (c *Config) SetAutoTargetConfig(key string, target Target) {
	if c.autoTargetsConfig == nil {
		c.autoTargetsConfig = make(map[string]*Target)
	}
	c.autoTargetsConfig[key] = &target
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
		case "dcos", "mesosphere", "kubernetes":
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
					/*
						mapTargets := make(map[string]bool)
						mgr := s.C.AutoTargets[manager]
						for _, v := range mgr.GetTargets() {
							mapTargets[v] = true
						}
						s.DeleteTargets(mapTargets)
						mgr.Targets = []string{}
						s.C.AutoTargets[manager] = mgr
					*/
				}()

				for {
					if stopDiscoverer() {
						break
					}
					switch manager {
					case "dcos", "marathon":
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
							log.Debugf("Autodiscovery: marathon task fetch complete.")
							break
						case <-time.After(taskTimeout * time.Second):
							log.Debugf("Autodiscovery: marathon task fetch timeout. continuing...")
							continue
						}
						newTargets := make(map[string]bool)
						atConfig := *s.C.GetAutoTargetConfig(manager)
						for _, target := range targetGroups {
							if atConfig.GetServiceName() == target.Source {
								for _, label := range target.Targets {
									app := string(label["__address__"])
									newTargets[app] = true
									log.Debugf("Autodiscovery(): adding dcos dragnet app %s", app)
								}
							}
						}
						atConfig.SetTargets(newTargets)
					case "kubernetes":
						ctx = context.Background()
						ctx, cancel = context.WithCancel(ctx)
						ts = make(chan []*targetgroup.Group)
						discovery := d.(*kubernetes.Discovery)
						go discovery.Run(ctx, ts)
						select {
						case <-ts:
							targetGroups = <-ts
							cancel()
							log.Debugf("Autodiscovery: kubernetes task fetch complete.")
							break
						case <-time.After(taskTimeout * time.Second):
							log.Debugf("Autodiscovery: kubernetes task fetch timeout. continuing...")
							continue
						}
						newTargets := make(map[string]bool)
						atConfig := *s.C.GetAutoTargetConfig(manager)
						for _, target := range targetGroups {
							source := string(target.Labels["__meta_kubernetes_pod_label_app"])
							if atConfig.GetServiceName() == source {
								for _, label := range target.Targets {
									app := string(label["__address__"])
									newTargets[app] = true
									log.Debugf("Autodiscovery(): adding kubernetes dragnet app %s", app)
								}
							}
						}
						atConfig.SetTargets(newTargets)
					default:
						return nil
					}

					if stopDiscoverer() {
						break
					}

					//refreshInterval := s.C.AutoTargets[manager].RefreshInterval
					//refreshInterval.String()
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

type Target interface {
	GetServiceName() string
	GetConfig() interface{}
	GetTargets() map[string]bool
	SetTargets(map[string]bool)
}

type KubernetesTarget struct {
	ServiceName string              `yaml:"service_name,omitempty"`
	targets     map[string]bool     `yaml:"-"`
	Targets     []string            `yaml:"targets,omitempty"`
	Config      kubernetes.SDConfig `yaml:",inline"`
}

func (t KubernetesTarget) GetServiceName() string {
	return t.ServiceName
}

func (t KubernetesTarget) GetConfig() interface{} {
	return t.Config
}

func (t KubernetesTarget) GetTargets() map[string]bool {
	return t.targets
}

func (t *KubernetesTarget) SetTargets(targets map[string]bool) {
	var listTargets []string
	for key := range targets {
		listTargets = append(listTargets, key)
	}
	t.targets = targets
	t.Targets = listTargets
}

type MarathonTarget struct {
	ServiceName string            `yaml:"service_name,omitempty"`
	targets     map[string]bool   `yaml:"-"`
	Targets     []string          `yaml:"targets,omitempty"`
	Config      marathon.SDConfig `yaml:",inline"`
}

func (t MarathonTarget) GetServiceName() string {
	return t.ServiceName
}

func (t MarathonTarget) GetConfig() interface{} {
	return t.Config
}

func (t MarathonTarget) GetTargets() map[string]bool {
	return t.targets
}

func (t *MarathonTarget) SetTargets(targets map[string]bool) {
	var listTargets []string
	for key := range targets {
		listTargets = append(listTargets, key)
	}
	t.targets = targets
	t.Targets = listTargets
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

func getMarathonDiscoveryConfig(config interface{}) (*MarathonTarget, error) {
	var (
		cfg        MarathonTarget
		err        error
		yamlConfig []byte
	)
	yamlConfig, err = yaml.Marshal(config)
	if err != nil {
		return nil, err
	}
	err = yaml.Unmarshal(yamlConfig, &cfg)
	if err != nil {
		return nil, err
	}
	return &cfg, nil
}

func getKubernetesDiscoveryConfig(config interface{}) (*KubernetesTarget, error) {
	var (
		cfg        KubernetesTarget
		err        error
		yamlConfig []byte
	)
	yamlConfig, err = yaml.Marshal(config)
	if err != nil {
		return nil, err
	}
	err = yaml.Unmarshal(yamlConfig, &cfg)
	if err != nil {
		return nil, err
	}
	return &cfg, nil
}
