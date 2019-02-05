package prober

import (
	"net"
	"time"

	//"github.com/go-kit/kit/log"
	//"github.com/go-kit/kit/log/level"
	log "github.com/sirupsen/logrus"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	probeDNSLookupTimeSeconds *prometheus.GaugeVec
	probeIPProtocolGauge      *prometheus.GaugeVec
)

// Returns the IP for the IPProtocol and lookup time.
func chooseProtocol(IPProtocol string, fallbackIPProtocol bool, source string, target string, registry *prometheus.Registry) (ip *net.IPAddr, lookupTime float64, err error) {
	var fallbackProtocol string
	metricsMutex.Lock()
	if probeDNSLookupTimeSeconds == nil {
		probeDNSLookupTimeSeconds = prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "dragnet_probe_dns_lookup_time_seconds",
			Help: "Returns the time taken for probe dns lookup in seconds",
		}, []string{"source", "target"})
		registry.MustRegister(probeDNSLookupTimeSeconds)
	}

	if probeIPProtocolGauge == nil {
		probeIPProtocolGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "dragnet_probe_ip_protocol",
			Help: "Specifies whether probe ip protocol is IP4 or IP6",
		}, []string{"source", "target"})
		registry.MustRegister(probeIPProtocolGauge)
	}
	metricsMutex.Unlock()

	if IPProtocol == "ip6" || IPProtocol == "" {
		IPProtocol = "ip6"
		fallbackProtocol = "ip4"
	} else {
		IPProtocol = "ip4"
		fallbackProtocol = "ip6"
	}

	if IPProtocol == "ip6" {
		fallbackProtocol = "ip4"
	} else {
		fallbackProtocol = "ip6"
	}

	log.Infof("Resolving target address. ip_protocol=%v", IPProtocol)
	resolveStart := time.Now()

	defer func() {
		lookupTime = time.Since(resolveStart).Seconds()
		probeDNSLookupTimeSeconds.With(prometheus.Labels{"source": source, "target": target}).Add(lookupTime)
	}()

	ip, err = net.ResolveIPAddr(IPProtocol, target)
	if err != nil {
		if !fallbackIPProtocol {
			log.Errorf("Resolution with IP protocol failed (fallback_ip_protocol is false). err=%v", err)
		} else {
			log.Warnf("Resolution with IP protocol failed, attempting fallback protocol. fallback_protocol=%v err=%v", fallbackProtocol, err)
			ip, err = net.ResolveIPAddr(fallbackProtocol, target)
		}

		if err != nil {
			return ip, 0.0, err
		}
	}

	if ip.IP.To4() == nil {
		probeIPProtocolGauge.With(prometheus.Labels{"source": source, "target": target}).Set(6)
	} else {
		probeIPProtocolGauge.With(prometheus.Labels{"source": source, "target": target}).Set(4)
	}

	log.Infof("Resolved target address. ip=%v", ip)
	return ip, lookupTime, nil
}
