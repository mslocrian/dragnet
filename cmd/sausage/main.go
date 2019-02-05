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

	"github.com/mslocrian/sausage/internal/config"
	"github.com/mslocrian/sausage/internal/environment"
	"github.com/mslocrian/sausage/internal/probers"

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
)

var (
	sc = &config.SafeConfig{
		C: &config.Config{},
	}
	probeSuccessGauge  *prometheus.GaugeVec
	probeDurationGauge *prometheus.GaugeVec
	registry           *prometheus.Registry
	sausageVersion     string
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
	var wg = sync.WaitGroup{}
	var source string
	_ = wg
	targets := c.GetTargets()

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
		source = environment.GetVar("env:SAUSAGE_HOST")
	}
	for target := range targets {
		start := time.Now()
		success := prober(ctx, source, target, module, registry)
		duration := time.Since(start).Seconds()
		probeDurationGauge.With(prometheus.Labels{"target": target}).Set(duration)
		if success {
			probeSuccessGauge.With(prometheus.Labels{"target": target}).Set(1)
		}
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

func init() {
	prometheus.MustRegister(version.NewCollector("sausage"))

	probeSuccessGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "sausage_probe_success",
		Help: "Displays whether or not the probe was a success",
	}, []string{"target"})

	probeDurationGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "sausage_probe_duration_seconds",
		Help: "Returns how long the probe took to complete in seconds",
	}, []string{"target"})
}

func main() {
	var (
		configCheck    = flag.Bool("config.check", false, "Validate the config file and exit.")
		configLogLevel = flag.String("log.level", "info", "The sausage log level. Log levels are: debug, info, warn, error, fatal, panic.")
		configFile     = flag.String("config.file", "/etc/sausage.yml", "The sausage configuration file.")
		listenAddress  = flag.String("web.listen-address", ":9600", "The address to listen on for HTTP requests.")
		sourceHost     = flag.String("config.source-host", "", "The address to set source host in metrics (default: $SAUSAGE_HOST)")
		versionFlag    = flag.Bool("version", false, "Print version information.")
	)
	flag.Parse()

	if *versionFlag {
		fmt.Fprintf(os.Stdout, "sausage %s\n", sausageVersion)
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
				log.Info("Reloaded config file.")
			case rc := <-reloadCh:
				if err := sc.ReloadConfig(*configFile); err != nil {
					log.Errorf("Error reloading config: %s", err)
					rc <- err
				} else {
					log.Info("Reloaded config file.")
					registry = prometheus.NewRegistry()
					registry.MustRegister(probeSuccessGauge)
					registry.MustRegister(probeDurationGauge)
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
			registry = prometheus.NewRegistry()
			registry.MustRegister(probeSuccessGauge)
			registry.MustRegister(probeDurationGauge)
		})
	http.Handle("/metrics", promhttp.Handler())
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html>
    <head><title>Sausage - Cluster Mesh Latency Thingy</title></head>
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

	log.Infof("sausage listening on address %v", *listenAddress)
	if err := http.ListenAndServe(*listenAddress, nil); err != nil {
		log.Fatalf("Error starting HTTP server! err=%v", err)
	}
	os.Exit(0)
}
