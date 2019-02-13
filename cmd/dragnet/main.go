package main

import (
	"context"
	"flag"
	"fmt"
	"math/rand"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	yaml "gopkg.in/yaml.v2"

	"github.com/mslocrian/dragnet/internal/config"
	"github.com/mslocrian/dragnet/internal/environment"
	"github.com/mslocrian/dragnet/internal/probers"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/version"
	log "github.com/sirupsen/logrus"
)

const (
	letterBytes   = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	letterIdxBits = 6                    // 6 bits to represent a letter index
	letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
	letterIdxMax  = 63 / letterIdxBits   // # of letter indices fitting in 63 bits
	sleepTime     = 60                   // Hard coded time to sleep between auto discovery jobs
)

var (
	sc = &config.SafeConfig{
		C: &config.Config{},
	}

	probeSuccessGauge  *prometheus.GaugeVec
	probeDurationGauge *prometheus.GaugeVec
	registry           *prometheus.Registry
	dragnetVersion     string
	timeoutOffset      = flag.Float64("timeout-offset", 0.5, "Offset to subtract from probe timeout in seconds.")
)

func randomString(n int) string {
	var src = rand.NewSource(time.Now().UnixNano())
	b := make([]byte, n)
	for i, cache, remain := n-1, src.Int63(), letterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = src.Int63(), letterIdxMax
		}
		if idx := int(cache & letterIdxMask); idx < len(letterBytes) {
			b[i] = letterBytes[idx]
			i--
		}
		cache >>= letterIdxBits
		remain--
	}

	return string(b)
}

func generateHandler(w http.ResponseWriter, r *http.Request) {
	var (
		err  error
		size int
	)
	sizeString := r.URL.Query().Get("size")
	if sizeString == "" {
		size = 1
	} else {
		size, err = strconv.Atoi(sizeString)
		if err != nil {
			size = 1
		}
	}
	if (size <= 0) || (size > 1024) {
		size = 1
	}
	w.Write([]byte(randomString(size * 1024)))
}

func probeHandler(w http.ResponseWriter, r *http.Request, c *config.Config, registry *prometheus.Registry) {
	var (
		wg     sync.WaitGroup
		source string
	)
	wg = sync.WaitGroup{}
    log.Errorf("HERE I AM 1")
	targets := c.GetTargets()
    log.Errorf("HERE I AM 2: targets=%#v", targets)

	// If a timeout is configured via the Prometheus header, add it to the request
	var timeoutSeconds float64
	if v := r.Header.Get("X-Prometheus-Scrape-Timeout-Seconds"); v != "" {
		var err error
		timeoutSeconds, err = strconv.ParseFloat(v, 64)
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to parse timeout from Prometheus header: %s", err), http.StatusInternalServerError)
			return
		}
	}
	if timeoutSeconds == 0 {
		timeoutSeconds = 10
	}
	// just going to set the default to 10 until we are further along
	timeoutSeconds = 10
	timeoutSeconds -= *timeoutOffset
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSeconds*float64(time.Second)))
	defer cancel()
	r = r.WithContext(ctx)

	prober := prober.ProbeHTTP
	module := c.Modules["http_2xx"]
	if c.SourceHost != "" {
		source = environment.GetVar(c.SourceHost)
	} else {
		source = environment.GetVar("env:DRAGNET_HOST")
	}

	maxGoRoutines := 30
	guard := make(chan struct{}, maxGoRoutines)
	for target := range targets {
		guard <- struct{}{}
		wg.Add(1)
		go func(t string) {
			start := time.Now()
			success := prober(ctx, source, target, module, registry)
			duration := time.Since(start).Seconds()
			probeDurationGauge.With(prometheus.Labels{"target": target}).Set(duration)
			if success {
				probeSuccessGauge.With(prometheus.Labels{"target": target}).Set(1)
			}
			<-guard
			wg.Done()
		}(target)
		wg.Wait()
	}

	h := promhttp.HandlerFor(registry, promhttp.HandlerOpts{})
	h.ServeHTTP(w, r)
}

func setLogLevel(l string) log.Level {
	switch strings.ToLower(l) {
	case "debug":
		return log.DebugLevel
	case "info":
		return log.InfoLevel
	case "warn":
		return log.WarnLevel
	case "error":
		return log.ErrorLevel
	case "fatal":
		return log.FatalLevel
	case "panic":
		return log.PanicLevel
	default:
		log.Warn(fmt.Sprintf("Unknown log level \"%s\". Defaulting to %s", l, log.InfoLevel))
		return log.InfoLevel
	}
}

func zeroMetricsRegistry(registry *prometheus.Registry) error {
	log.Debugf("registry=%#v", registry)
	return nil
}

func init() {
	prometheus.MustRegister(version.NewCollector("dragnet"))

	probeSuccessGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "dragnet_probe_success",
		Help: "Displays whether or not the probe was a success",
	}, []string{"target"})

	probeDurationGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "dragnet_probe_duration_seconds",
		Help: "Returns how long the probe took to complete in seconds",
	}, []string{"target"})
}

func main() {
	var (
		configCheck    = flag.Bool("config.check", false, "Validate the config file and exit.")
		configLogLevel = flag.String("log.level", "info", "The dragnet log level. Log levels are: debug, info, warn, error, fatal, panic.")
		configFile     = flag.String("config.file", "/etc/dragnet/dragnet.yml", "The dragnet configuration file.")
		listenAddress  = flag.String("web.listen-address", "0.0.0.0", "The address to listen on for HTTP requests.")
		listenPort     = flag.String("web.listen-port", "9600", "The address to listen on for HTTP requests.")
		sourceHost     = flag.String("config.source-host", "", "The address to set source host in metrics (default: $DRAGNET_HOST)")
		versionFlag    = flag.Bool("version", false, "Print version information.")
	)
	flag.Parse()

	if *versionFlag {
		fmt.Fprintf(os.Stdout, "dragnet %s\n", dragnetVersion)
		os.Exit(0)
	}

	log.SetLevel(setLogLevel(environment.GetVar(*configLogLevel)))

	if err := sc.ReloadConfig(*configFile); err != nil {
		log.Fatalf("Error loading config %s. err=%s", *configFile, err)
	}

	if *configCheck {
		log.Infof("Config file is ok. Exiting...")
		os.Exit(0)
	}

	if *sourceHost != "" {
		sc.C.SourceHost = environment.GetVar(*sourceHost)
	}

	registry = prometheus.NewRegistry()
	registry.MustRegister(probeSuccessGauge)
	registry.MustRegister(probeDurationGauge)

	hup := make(chan os.Signal, 1)
	reloadCh := make(chan chan error)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		for {
			select {
			case <-hup:
				if err := sc.ReloadConfig(*configFile); err != nil {
					log.Errorf("Error reloading config: %s", err)
					continue
				}
				zeroMetricsRegistry(registry)
				sc.StopAutoDiscoverers()
				sc.StartAutoDiscoverers()
				log.Info("Reloaded config file.")
			case rc := <-reloadCh:
				if err := sc.ReloadConfig(*configFile); err != nil {
					log.Errorf("Error reloading config: %s", err)
					rc <- err
				} else {
					zeroMetricsRegistry(registry)
					sc.StopAutoDiscoverers()
					sc.StartAutoDiscoverers()
					log.Info("Reloaded config file.")
					rc <- nil
				}
			}
		}
	}()

	http.HandleFunc("/-/reload",
		func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "POST" {
				w.WriteHeader(http.StatusMethodNotAllowed)
				fmt.Fprintf(w, "This endpoint requirers a POST request.\n")
				return
			}
			rc := make(chan error)
			reloadCh <- rc
			if err := <-rc; err != nil {
				http.Error(w, fmt.Sprintf("failed to reload config: %s", err), http.StatusInternalServerError)
			}
			fmt.Fprintf(w, "Configuration reloaded!\n")
		})

	http.Handle("/metrics", promhttp.Handler())

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html>
    <head><title>Dragnet - Cluster Mesh Latency Thingy</title></head>
    <body>
        Do work!
    </body>
    </html>`))
	})

	http.HandleFunc("/probe", func(w http.ResponseWriter, r *http.Request) {
		sc.Lock()
		conf := sc.C
		probeHandler(w, r, conf, registry)
		sc.Unlock()
	})

	http.HandleFunc("/generate", func(w http.ResponseWriter, r *http.Request) {
		generateHandler(w, r)
	})

	http.HandleFunc("/config", func(w http.ResponseWriter, r *http.Request) {
        type ConfigConversion struct {
            AutoTargets map[string]*config.Target `yaml:"autotargets,omitempty"`
            Includes []string `yaml:"include,omitempty"`
            Modules map[string]config.Module `yaml:"modules,omitempty"`
            SourceHost string `yaml:"source_host,omitempty"`
            Targets []string `yaml:"targets,omitempty"`
        }
        var cfg ConfigConversion
		sc.RLock()
        cfg.AutoTargets = sc.C.GetAutoTargets()
        cfg.Includes = sc.C.Includes
        cfg.Modules = sc.C.Modules
        cfg.SourceHost = sc.C.SourceHost
        cfg.Targets = sc.C.Targets
		c, err := yaml.Marshal(cfg)
		sc.RUnlock()
		if err != nil {
			log.Warnf("Error marshaling configuration. err=%v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		w.Header().Set("Content-Type", "text/plain")
		w.Write(c)
	})

	sc.StartAutoDiscoverers()

	address := environment.GetVar(*listenAddress)
	port := environment.GetVar(*listenPort)
	addressPort := fmt.Sprintf("%v:%v", address, port)
	log.Infof("dragnet listening on address %v", addressPort)
	if err := http.ListenAndServe(addressPort, nil); err != nil {
		log.Fatalf("Error starting HTTP server! err=%v", err)
	}
	os.Exit(0)
}
