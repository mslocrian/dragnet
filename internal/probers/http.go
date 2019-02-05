// Copyright 2016 The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package prober

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptrace"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	//"github.com/go-kit/kit/log"
	//"github.com/go-kit/kit/log/level"

	"github.com/prometheus/client_golang/prometheus"
	pconfig "github.com/prometheus/common/config"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/publicsuffix"

	"github.com/mslocrian/sausage/internal/config"
)

var (
	durationGaugeVec                *prometheus.GaugeVec
	contentLengthGauge              *prometheus.GaugeVec
	redirectsGauge                  *prometheus.GaugeVec
	isSSLGauge                      *prometheus.GaugeVec
	statusCodeGauge                 *prometheus.GaugeVec
	probeSSLEarliestCertExpiryGauge *prometheus.GaugeVec
	probeHTTPVersionGauge           *prometheus.GaugeVec
	probeFailedDueToRegex           *prometheus.GaugeVec
	probeHTTPLastModified           *prometheus.GaugeVec
	metricsMutex                    *sync.Mutex
)

func init() {
	metricsMutex = &sync.Mutex{}

}

func matchRegularExpressions(reader io.Reader, httpConfig config.HTTPProbe) bool {
	body, err := ioutil.ReadAll(reader)
	if err != nil {
		log.Errorf("Error reading HTTP body. err=%v", err)
		return false
	}
	for _, expression := range httpConfig.FailIfMatchesRegexp {
		re, err := regexp.Compile(expression)
		if err != nil {
			log.Errorf("Could not compile regular expression. regexp=%v err=%v", expression, err)
			return false
		}
		if re.Match(body) {
			log.Errorf("Body matched regular expression. regexp=%v", expression)
			return false
		}
	}
	for _, expression := range httpConfig.FailIfNotMatchesRegexp {
		re, err := regexp.Compile(expression)
		if err != nil {
			log.Errorf("Could not compile regular expression. regexp=%v err=%v", expression, err)
			return false
		}
		if !re.Match(body) {
			log.Errorf("Body did not match regular expression. regexp=%v", expression)
			return false
		}
	}
	return true
}

// roundTripTrace holds timings for a single HTTP roundtrip.
type roundTripTrace struct {
	tls           bool
	start         time.Time
	dnsDone       time.Time
	connectDone   time.Time
	gotConn       time.Time
	responseStart time.Time
	end           time.Time
}

// transport is a custom transport keeping traces for each HTTP roundtrip.
type transport struct {
	Transport http.RoundTripper
	traces    []*roundTripTrace
	current   *roundTripTrace
}

func newTransport(rt http.RoundTripper) *transport {
	return &transport{
		Transport: rt,
		traces:    []*roundTripTrace{},
	}
}

// RoundTrip switches to a new trace, then runs embedded RoundTripper.
func (t *transport) RoundTrip(req *http.Request) (*http.Response, error) {
	trace := &roundTripTrace{}
	if req.URL.Scheme == "https" {
		trace.tls = true
	}
	t.current = trace
	t.traces = append(t.traces, trace)
	return t.Transport.RoundTrip(req)
}

func (t *transport) DNSStart(_ httptrace.DNSStartInfo) {
	t.current.start = time.Now()
}
func (t *transport) DNSDone(_ httptrace.DNSDoneInfo) {
	t.current.dnsDone = time.Now()
}
func (ts *transport) ConnectStart(_, _ string) {
	t := ts.current
	// No DNS resolution because we connected to IP directly.
	if t.dnsDone.IsZero() {
		t.start = time.Now()
		t.dnsDone = t.start
	}
}
func (t *transport) ConnectDone(net, addr string, err error) {
	t.current.connectDone = time.Now()
}
func (t *transport) GotConn(_ httptrace.GotConnInfo) {
	t.current.gotConn = time.Now()
}
func (t *transport) GotFirstResponseByte() {
	t.current.responseStart = time.Now()
}

func ProbeHTTP(ctx context.Context, source string, target string, module config.Module, registry *prometheus.Registry) (success bool) {
	var redirects int
	metricsMutex.Lock()
	if durationGaugeVec == nil {
		durationGaugeVec = prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "sausage_probe_http_duration_seconds",
			Help: "Duration of http request by phase, summed over all redirects",
		}, []string{"phase", "source", "target"})
		registry.MustRegister(durationGaugeVec)
	}

	if contentLengthGauge == nil {
		contentLengthGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "sausage_probe_http_content_length",
			Help: "Length of http content response",
		}, []string{"source", "target"})
		registry.MustRegister(contentLengthGauge)
	}

	if redirectsGauge == nil {
		redirectsGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "sausage_probe_http_redirects",
			Help: "The number of redirects",
		}, []string{"source", "target"})
		registry.MustRegister(redirectsGauge)
	}

	if isSSLGauge == nil {
		isSSLGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "sausage_probe_http_ssl",
			Help: "Indicates if SSL was used for the final redirect",
		}, []string{"source", "target"})
		registry.MustRegister(isSSLGauge)
	}

	if statusCodeGauge == nil {
		statusCodeGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "sausage_probe_http_status_code",
			Help: "Response HTTP status code",
		}, []string{"source", "target"})
		registry.MustRegister(statusCodeGauge)
	}

	if probeSSLEarliestCertExpiryGauge == nil {
		probeSSLEarliestCertExpiryGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "sausage_probe_ssl_earliest_cert_expiry",
			Help: "Returns earliest SSL cert expiry in unixtime",
		}, []string{"source", "target"})
		registry.MustRegister(probeSSLEarliestCertExpiryGauge)
	}

	if probeHTTPVersionGauge == nil {
		probeHTTPVersionGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "sausage_probe_http_version",
			Help: "Returns the version of HTTP of the probe response",
		}, []string{"source", "target"})
		registry.MustRegister(probeHTTPVersionGauge)
	}

	if probeFailedDueToRegex == nil {
		probeFailedDueToRegex = prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "sausage_probe_failed_due_to_regex",
			Help: "Indicates if probe failed due to regex",
		}, []string{"source", "target"})
		registry.MustRegister(probeFailedDueToRegex)
	}

	if probeHTTPLastModified == nil {
		probeHTTPLastModified = prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "sausage_probe_http_last_modified_timestamp_seconds",
			Help: "Returns the Last-Modified HTTP response header in unixtime",
		}, []string{"source", "target"})
		registry.MustRegister(probeHTTPLastModified)
	}

	metricsMutex.Unlock()

	httpConfig := module.HTTP
	requestSize := module.Size
	if requestSize == 0 {
		requestSize = 1
	}

	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "http://" + target
	}

	targetURL, err := url.Parse(target)
	if err != nil {
		log.Errorf("Could not prase target URL. err=%v", err)
		return false
	}

	// Going to static set the uri path to the /generate endpoint
	targetURL.Path = "/generate"

	targetHost, targetPort, err := net.SplitHostPort(targetURL.Host)
	// If split fails, assuming it's a hostname without port part.
	if err != nil {
		targetHost = targetURL.Host
	}

	ip, lookupTime, err := chooseProtocol(module.HTTP.IPProtocol, module.HTTP.IPProtocolFallback, source, targetHost, registry)
	if err != nil {
		log.Errorf("Error resolving address. err=%v", err)
		return false
	}
	durationGaugeVec.With(prometheus.Labels{"phase": "resolve", "source": source, "target": target}).Add(lookupTime)

	httpClientConfig := module.HTTP.HTTPClientConfig
	if len(httpClientConfig.TLSConfig.ServerName) == 0 {
		// If there is no `server_name` in tls_config, use
		// the hostname of the target.
		httpClientConfig.TLSConfig.ServerName = targetHost
	}
	client, err := pconfig.NewClientFromConfig(httpClientConfig, target)
	if err != nil {
		log.Errorf("Error generating HTTP client. err=%v", err)
		return false
	}

	jar, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	if err != nil {
		log.Errorf("Error generating cookiejar. err=%v", err)
		return false
	}
	client.Jar = jar

	// Inject transport that tracks trace for each redirect.
	tt := newTransport(client.Transport)
	client.Transport = tt

	client.CheckRedirect = func(r *http.Request, via []*http.Request) error {
		log.Infof("Received redirect. url=%v", r.URL.String())
		redirects = len(via)
		if redirects > 10 || httpConfig.NoFollowRedirects {
			log.Infof("Not following redirect")
			return errors.New("don't follow redirects")
		}
		return nil
	}

	if httpConfig.Method == "" {
		httpConfig.Method = "GET"
	}

	// Replace the host field in the URL with the IP we resolved.
	origHost := targetURL.Host
	if targetPort == "" {
		targetURL.Host = "[" + ip.String() + "]"
	} else {
		targetURL.Host = net.JoinHostPort(ip.String(), targetPort)
	}

	var body io.Reader

	// If a body is configured, add it to the request.
	if httpConfig.Body != "" {
		body = strings.NewReader(httpConfig.Body)
	}

	request, err := http.NewRequest(httpConfig.Method, targetURL.String(), body)
	query := request.URL.Query()
	query.Add("size", fmt.Sprintf("%v", requestSize))
	request.URL.RawQuery = query.Encode()
	request.Host = origHost
	request = request.WithContext(ctx)
	if err != nil {
		log.Errorf("Error creating request. err=%v", err)
		return
	}

	for key, value := range httpConfig.Headers {
		if strings.Title(key) == "Host" {
			request.Host = value
			continue
		}
		request.Header.Set(key, value)
	}

	log.Infof("Making HTTP request. url=%v host=%v", request.URL.String(), request.Host)

	trace := &httptrace.ClientTrace{
		DNSStart:             tt.DNSStart,
		DNSDone:              tt.DNSDone,
		ConnectStart:         tt.ConnectStart,
		ConnectDone:          tt.ConnectDone,
		GotConn:              tt.GotConn,
		GotFirstResponseByte: tt.GotFirstResponseByte,
	}
	request = request.WithContext(httptrace.WithClientTrace(request.Context(), trace))

	resp, err := client.Do(request)
	// Err won't be nil if redirects were turned off. See https://github.com/golang/go/issues/3795
	if err != nil && resp == nil {
		log.Errorf("Error for http request. err=%v", err)
	} else {
		requestErrored := (err != nil)

		log.Infof("Received HTTP  Response. status_code=%v", resp.StatusCode)
		if len(httpConfig.ValidStatusCodes) != 0 {
			for _, code := range httpConfig.ValidStatusCodes {
				if resp.StatusCode == code {
					success = true
					break
				}
			}
			if !success {
				log.Infof("Invalid HTTP response status code. status_code=%v valid_status_code=%v", resp.StatusCode, httpConfig.ValidStatusCodes)
			}
		} else if 200 <= resp.StatusCode && resp.StatusCode < 300 {
			success = true
		} else {
			log.Infof("Invalid HTTP response sttus code, wanted 2xx. status_code=%v", resp.StatusCode)
		}

		if success && (len(httpConfig.FailIfMatchesRegexp) > 0 || len(httpConfig.FailIfNotMatchesRegexp) > 0) {
			success = matchRegularExpressions(resp.Body, httpConfig)
			if success {
				probeFailedDueToRegex.With(prometheus.Labels{"source": source, "target": target}).Set(0)
			} else {
				probeFailedDueToRegex.With(prometheus.Labels{"source": source, "target": target}).Set(1)
			}
		}

		if resp != nil && !requestErrored {
			_, err = io.Copy(ioutil.Discard, resp.Body)
			if err != nil {
				log.Infof("Failed to read HTTP response body. err=%v", err)
				success = false
			}

			resp.Body.Close()
		}

		// At this point body is fully read and we can write end time.
		tt.current.end = time.Now()

		// Check if there is a Last-Modified HTTP response header.
		if t, err := http.ParseTime(resp.Header.Get("Last-Modified")); err == nil {
			probeHTTPLastModified.With(prometheus.Labels{"source": source, "target": target}).Set(float64(t.Unix()))
		}

		var httpVersionNumber float64
		httpVersionNumber, err = strconv.ParseFloat(strings.TrimPrefix(resp.Proto, "HTTP/"), 64)
		if err != nil {
			log.Errorf("Error parsing version number from HTTP version. err=%v", err)
		}
		probeHTTPVersionGauge.With(prometheus.Labels{"source": source, "target": target}).Set(httpVersionNumber)

		if len(httpConfig.ValidHTTPVersions) != 0 {
			found := false
			for _, version := range httpConfig.ValidHTTPVersions {
				if version == resp.Proto {
					found = true
					break
				}
			}
			if !found {
				log.Errorf("Invalid HTTP version number. version=%v", httpVersionNumber)
				success = false
			}
		}

	}

	if resp == nil {
		resp = &http.Response{}
	}
	for i, trace := range tt.traces {
		log.Infof("Response timings for roundtrip. roundtrip=%v start=%v dnsDone=%v connectDone=%v gotConn=%v responseStart=%v end=%v", i, trace.start, trace.dnsDone, trace.connectDone, trace.gotConn, trace.responseStart, trace.end)
		// We get the duration for the first request from chooseProtocol.
		if i != 0 {
			durationGaugeVec.With(prometheus.Labels{"phase": "resolve", "source": source, "target": target}).Add(trace.dnsDone.Sub(trace.start).Seconds())
			//durationGaugeVec.WithLabelValues("resolve").Add(trace.dnsDone.Sub(trace.start).Seconds())
		}
		// Continue here if we never got a connection because a request failed.
		if trace.gotConn.IsZero() {
			continue
		}
		if trace.tls {
			// dnsDone must be set if gotConn was set.
			//durationGaugeVec.WithLabelValues("connect").Add(trace.connectDone.Sub(trace.dnsDone).Seconds())
			//durationGaugeVec.WithLabelValues("tls").Add(trace.gotConn.Sub(trace.dnsDone).Seconds())
			durationGaugeVec.With(prometheus.Labels{"phase": "connect", "source": source, "target": target}).Add(trace.connectDone.Sub(trace.dnsDone).Seconds())
			durationGaugeVec.With(prometheus.Labels{"phase": "tls", "source": source, "target": target}).Add(trace.gotConn.Sub(trace.dnsDone).Seconds())
		} else {
			//durationGaugeVec.WithLabelValues("connect").Add(trace.gotConn.Sub(trace.dnsDone).Seconds())
			durationGaugeVec.With(prometheus.Labels{"phase": "connect", "source": source, "target": target}).Add(trace.gotConn.Sub(trace.dnsDone).Seconds())
		}

		// Continue here if we never got a response from the server.
		if trace.responseStart.IsZero() {
			continue
		}
		//durationGaugeVec.WithLabelValues("processing").Add(trace.responseStart.Sub(trace.gotConn).Seconds())
		durationGaugeVec.With(prometheus.Labels{"phase": "processing", "source": source, "target": target}).Add(trace.responseStart.Sub(trace.gotConn).Seconds())

		// Continue here if we never read the full response from the server.
		// Usually this means that request either failed or was redirected.
		if trace.end.IsZero() {
			continue
		}
		//durationGaugeVec.WithLabelValues("transfer").Add(trace.end.Sub(trace.responseStart).Seconds())
		durationGaugeVec.With(prometheus.Labels{"phase": "transfer", "source": source, "target": target}).Add(trace.end.Sub(trace.responseStart).Seconds())
	}

	if resp.TLS != nil {
		isSSLGauge.With(prometheus.Labels{"source": source, "target": target}).Set(float64(1))
		probeSSLEarliestCertExpiryGauge.With(prometheus.Labels{"source": source, "target": target}).Set(float64(getEarliestCertExpiry(resp.TLS).Unix()))
		if httpConfig.FailIfSSL {
			log.Errorf("Final request was over SSL")
			success = false
		}
	} else if httpConfig.FailIfNotSSL {
		log.Errorf("Final request was not over SSL")
		success = false
	}

	statusCodeGauge.With(prometheus.Labels{"source": source, "target": target}).Set(float64(resp.StatusCode))
	contentLengthGauge.With(prometheus.Labels{"source": source, "target": target}).Set(float64(resp.ContentLength))
	redirectsGauge.With(prometheus.Labels{"source": source, "target": target}).Set(float64(redirects))
	return
}
