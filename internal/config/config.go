package config

import (
	"fmt"
	"io/ioutil"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	yaml "gopkg.in/yaml.v2"

	"github.com/prometheus/common/config"
	"github.com/prometheus/common/model"
	"github.com/prometheus/common/promlog"
	"github.com/prometheus/prometheus/discovery/marathon"
)

type Config struct {
	AutoTargets       map[string]AutoTarget `yaml:"autotargets"`
	DiscoveryManagers map[string]interface{}
	Includes          []string          `yaml:"include"`
	Modules           map[string]Module `yaml:"modules"`
	Targets           []string          `yaml:"targets"`
	SourceHost        string            `yaml:"source_host"`
	targets           map[string]bool
}

type SafeConfig struct {
	sync.RWMutex
	C *Config
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
				// stegen - perhaps do something else here?
				continue
			}
			c.DiscoveryManagers[key] = discovery
			/*
			   ctx := context.Background()
			   ts := make(chan []*targetgroup.Group)
			   go discovery.Run(ctx, ts)
			   newTargets := <-ts
			   for _, target := range newTargets {
			       // do the service names match? that's what we are interested in!
			       if atConfig.ServiceName == target.Source {
			           for _, label := range target.Targets {
			               t := string(label["__address__"])
			               log.Debugf("t=%v", t)
			               targets[t] = true
			           }
			       }
			   }
			*/
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
	for k, _ := range t {
		targets[k] = true
	}
	s.C.SetTargets(targets)
	s.Unlock()
}

type AutoTarget struct {
	Servers          []string                `yaml:"servers,omitempty"`
	ServiceName      string                  `yaml:"service_name"`
	RefreshInterval  model.Duration          `yaml:"refresh_interval,omitempty"`
	AuthToken        config.Secret           `yaml:"auth_token"`
	HTTPClientConfig config.HTTPClientConfig `yaml:",inline"`
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
