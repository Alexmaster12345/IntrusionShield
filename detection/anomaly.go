package detection

import (
	"log"
	"math"
	"sync"
	"time"

	"github.com/Alexmaster12345/IntrusionShield/parser"
)

// AnomalyAlert describes a statistical anomaly event.
type AnomalyAlert struct {
	Timestamp   time.Time
	Type        string  // "packet_rate", "port_scan", "dns_flood"
	Description string
	Value       float64
	Mean        float64
	StdDev      float64
	ZScore      float64
	SrcIP       string
}

// Detector tracks per-second packet rates and raises anomaly alerts
// when the Z-score exceeds the configured threshold.
type Detector struct {
	windowSize int
	threshold  float64
	window     []float64 // rolling packet-count samples
	mu         sync.Mutex

	// Per-source connection tracking for port scan detection
	srcPorts map[string]map[uint16]time.Time

	AlertCh chan AnomalyAlert

	// Current-second counters
	currentTick  int64
	currentCount float64
}

// NewDetector creates an anomaly detector with the given window size and Z-score threshold.
func NewDetector(windowSize int, threshold float64) *Detector {
	d := &Detector{
		windowSize: windowSize,
		threshold:  threshold,
		window:     make([]float64, 0, windowSize),
		srcPorts:   make(map[string]map[uint16]time.Time),
		AlertCh:    make(chan AnomalyAlert, 200),
	}
	return d
}

// Observe feeds a packet into the anomaly detector.
func (d *Detector) Observe(p *parser.Packet) {
	d.mu.Lock()
	defer d.mu.Unlock()

	tick := p.Timestamp.Unix()

	if tick != d.currentTick {
		// New second — flush the previous second's count into the window
		if d.currentTick != 0 {
			d.addSample(d.currentCount)
			d.checkRateAnomaly(p.Timestamp)
		}
		d.currentTick = tick
		d.currentCount = 0
	}
	d.currentCount++

	// Port scan detection: track unique dst ports per src IP in 10-second window
	if p.Protocol == "TCP" && p.DstPort > 0 {
		src := p.SrcIP.String()
		if d.srcPorts[src] == nil {
			d.srcPorts[src] = make(map[uint16]time.Time)
		}
		d.srcPorts[src][p.DstPort] = p.Timestamp

		// Expire old entries and count unique ports in last 10s
		cutoff := p.Timestamp.Add(-10 * time.Second)
		for port, ts := range d.srcPorts[src] {
			if ts.Before(cutoff) {
				delete(d.srcPorts[src], port)
			}
		}
		if len(d.srcPorts[src]) >= 20 {
			d.emit(AnomalyAlert{
				Timestamp:   p.Timestamp,
				Type:        "port_scan",
				Description: "Port scan: " + src + " contacted 20+ distinct ports in 10s",
				Value:       float64(len(d.srcPorts[src])),
				SrcIP:       src,
			})
			// Reset to avoid flooding
			d.srcPorts[src] = make(map[uint16]time.Time)
		}
	}
}

func (d *Detector) addSample(v float64) {
	if len(d.window) >= d.windowSize {
		d.window = d.window[1:]
	}
	d.window = append(d.window, v)
}

func (d *Detector) checkRateAnomaly(ts time.Time) {
	if len(d.window) < 10 {
		return
	}
	mean, stddev := stats(d.window)
	if stddev == 0 {
		return
	}
	latest := d.window[len(d.window)-1]
	z := (latest - mean) / stddev

	if math.Abs(z) >= d.threshold {
		log.Printf("[anomaly] packet rate spike: count=%.0f mean=%.1f stddev=%.1f z=%.2f", latest, mean, stddev, z)
		d.emit(AnomalyAlert{
			Timestamp:   ts,
			Type:        "packet_rate",
			Description: "Packet rate anomaly detected",
			Value:       latest,
			Mean:        mean,
			StdDev:      stddev,
			ZScore:      z,
		})
	}
}

func (d *Detector) emit(a AnomalyAlert) {
	select {
	case d.AlertCh <- a:
	default:
	}
}

func stats(data []float64) (mean, stddev float64) {
	if len(data) == 0 {
		return
	}
	sum := 0.0
	for _, v := range data {
		sum += v
	}
	mean = sum / float64(len(data))

	variance := 0.0
	for _, v := range data {
		d := v - mean
		variance += d * d
	}
	stddev = math.Sqrt(variance / float64(len(data)))
	return
}
