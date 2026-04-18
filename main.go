package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Alexmaster12345/IntrusionShield/alert"
	"github.com/Alexmaster12345/IntrusionShield/capture"
	"github.com/Alexmaster12345/IntrusionShield/config"
	"github.com/Alexmaster12345/IntrusionShield/dashboard"
	"github.com/Alexmaster12345/IntrusionShield/detection"
	"github.com/Alexmaster12345/IntrusionShield/storage"
)

func main() {
	cfgPath := flag.String("config", "config.json", "path to config file")
	iface := flag.String("iface", "", "network interface to capture on (overrides config)")
	verbose := flag.Bool("verbose", false, "print each packet to stdout")
	noStore := flag.Bool("no-db", false, "disable PostgreSQL storage")
	flag.Parse()

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}
	if *iface != "" {
		cfg.Interface = *iface
	}

	setupLogging(cfg.LogFile)
	log.Printf("IntrusionShield starting — interface=%s", cfg.Interface)

	// --- Storage ---
	var db *storage.DB
	if !*noStore {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		db, err = storage.Connect(ctx, cfg.DatabaseURL)
		cancel()
		if err != nil {
			log.Printf("[main] DB unavailable (%v) — running without persistence", err)
			db = nil
		}
	}

	// --- Detection engine ---
	engine, err := detection.NewEngine(cfg.RulesFile)
	if err != nil {
		log.Fatalf("create detection engine: %v", err)
	}

	// --- Anomaly detector ---
	anomaly := detection.NewDetector(cfg.WindowSize, cfg.AnomalyThreshold)

	// --- Notifier ---
	notifier := alert.NewNotifier(cfg)

	// --- Dashboard ---
	var dash *dashboard.Server
	if db != nil {
		dash = dashboard.NewServer(db, cfg.DashboardPort)
		dash.Start()
	}

	// --- Packet capture ---
	sniffer := capture.New(cfg)
	if err := sniffer.Start(); err != nil {
		log.Fatalf("start capture: %v", err)
	}

	// --- Main pipeline ---
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigCh
		log.Printf("[main] signal %s received — shutting down", sig)
		cancel()
	}()

	log.Println("[main] pipeline running — press Ctrl+C to stop")
	var totalPackets, totalAlerts uint64

loop:
	for {
		select {
		case <-ctx.Done():
			break loop

		case pkt, ok := <-sniffer.PacketCh:
			if !ok {
				break loop
			}
			totalPackets++

			if *verbose {
				capture.PrintMetadata(pkt)
			}

			// Feed detection engine
			engine.Inspect(pkt)

			// Feed anomaly detector
			anomaly.Observe(pkt)

			// Persist packet summary
			if db != nil {
				go func() {
					bgCtx, c := context.WithTimeout(context.Background(), 3*time.Second)
					defer c()
					_ = db.SavePacket(bgCtx, pkt)
				}()
			}

		case a := <-engine.AlertCh:
			totalAlerts++
			log.Printf("[ALERT] [%s] %s  %s:%d → %s:%d",
				severityLabel(a.Severity), a.Msg,
				ipStr(a.SrcIP), a.SrcPort, ipStr(a.DstIP), a.DstPort)

			notifier.Dispatch(a)
			if dash != nil {
				dash.AddAlert(a)
			}
			if db != nil {
				go func() {
					bgCtx, c := context.WithTimeout(context.Background(), 3*time.Second)
					defer c()
					_ = db.SaveAlert(bgCtx, a)
				}()
			}

		case a := <-anomaly.AlertCh:
			log.Printf("[ANOMALY] %s — z=%.2f", a.Description, a.ZScore)
			notifier.DispatchAnomaly(a)
			if db != nil {
				go func() {
					bgCtx, c := context.WithTimeout(context.Background(), 3*time.Second)
					defer c()
					_ = db.SaveAnomaly(bgCtx, a)
				}()
			}
		}
	}

	sniffer.Stop()
	if dash != nil {
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		dash.Stop(shutCtx)
	}
	log.Printf("[main] done — %d packets processed, %d alerts generated", totalPackets, totalAlerts)
}

func setupLogging(logFile string) {
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)
	if logFile == "" {
		return
	}
	f, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("[main] cannot open log file %s: %v", logFile, err)
		return
	}
	log.SetOutput(f)
}

func severityLabel(s int) string {
	switch s {
	case 1:
		return "LOW"
	case 2:
		return "MEDIUM"
	case 3:
		return "HIGH"
	default:
		return "UNKNOWN"
	}
}

func ipStr(ip interface{ String() string }) string {
	if ip == nil {
		return "<nil>"
	}
	return ip.String()
}

func init() {
	fmt.Println(`
 ___     _                    _            ____  _     _      _     _
|_ _|_ _| |_ _ _ _  _ _____ (_)___ _ _   / ___|| |__ (_) ___| | __| |
 | || ' \  _| '_| || (_-< \ / / _ \ ' \  \___ \| '_ \| |/ _ \ |/ _' |
|___|_||_\__|_|  \_,_/__/\_V /\___/_||_| |____/|_| |_|_|\___/_|\__,_|
                                                   Network IDS v1.0.0
`)
}
