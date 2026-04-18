package capture

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"

	"github.com/Alexmaster12345/IntrusionShield/config"
	"github.com/Alexmaster12345/IntrusionShield/parser"
)

// Sniffer captures packets from a network interface.
type Sniffer struct {
	cfg      *config.Config
	handle   *pcap.Handle
	writer   *pcapgo.Writer
	outFile  *os.File
	PacketCh chan *parser.Packet
	StopCh   chan struct{}
}

// New creates a new Sniffer. Call Start() to begin capturing.
func New(cfg *config.Config) *Sniffer {
	return &Sniffer{
		cfg:      cfg,
		PacketCh: make(chan *parser.Packet, 1000),
		StopCh:   make(chan struct{}),
	}
}

// Start opens the interface and begins capturing.
func (s *Sniffer) Start() error {
	var err error

	s.handle, err = pcap.OpenLive(
		s.cfg.Interface,
		s.cfg.SnapLen,
		s.cfg.Promiscuous,
		pcap.BlockForever,
	)
	if err != nil {
		return fmt.Errorf("open interface %s: %w", s.cfg.Interface, err)
	}

	filter := s.cfg.BPFFilter
	if filter == "" {
		filter = DefaultFilter()
	}
	if filter != "" {
		if err := s.handle.SetBPFFilter(filter); err != nil {
			return fmt.Errorf("set BPF filter %q: %w", filter, err)
		}
		log.Printf("[capture] BPF filter: %s", filter)
	}

	if s.cfg.PcapOutput != "" {
		s.outFile, err = os.Create(s.cfg.PcapOutput)
		if err != nil {
			return fmt.Errorf("create pcap file: %w", err)
		}
		s.writer = pcapgo.NewWriter(s.outFile)
		if err := s.writer.WriteFileHeader(uint32(s.cfg.SnapLen), layers.LinkTypeEthernet); err != nil {
			return fmt.Errorf("write pcap header: %w", err)
		}
		log.Printf("[capture] saving packets to %s", s.cfg.PcapOutput)
	}

	log.Printf("[capture] listening on %s (promiscuous=%v)", s.cfg.Interface, s.cfg.Promiscuous)

	go s.loop()
	return nil
}

// Stop signals the capture loop to exit.
func (s *Sniffer) Stop() {
	close(s.StopCh)
	if s.handle != nil {
		s.handle.Close()
	}
	if s.outFile != nil {
		s.outFile.Close()
	}
}

func (s *Sniffer) loop() {
	src := gopacket.NewPacketSource(s.handle, s.handle.LinkType())
	src.NoCopy = true

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	var count uint64
	start := time.Now()

	for {
		select {
		case <-s.StopCh:
			log.Printf("[capture] stopped after %d packets in %s", count, time.Since(start))
			return
		case sig := <-sigCh:
			log.Printf("[capture] received signal %s — stopping", sig)
			s.Stop()
			return
		case pkt, ok := <-src.Packets():
			if !ok {
				return
			}

			if s.writer != nil {
				if err := s.writer.WritePacket(pkt.Metadata().CaptureInfo, pkt.Data()); err != nil {
					log.Printf("[capture] write pcap error: %v", err)
				}
			}

			parsed := parser.Parse(pkt)
			if parsed != nil {
				count++
				select {
				case s.PacketCh <- parsed:
				default:
					// Drop if pipeline is full — prefer capture continuity
				}
			}
		}
	}
}

// PrintMetadata prints packet metadata to stdout — used for the CLI sniffer mode.
func PrintMetadata(p *parser.Packet) {
	ts := p.Timestamp.Format("15:04:05.000000")
	fmt.Printf("[%s] %s  %s → %s  len=%d",
		ts, p.Protocol, p.SrcIP, p.DstIP, p.Length)

	if p.SrcPort > 0 || p.DstPort > 0 {
		fmt.Printf("  %d → %d", p.SrcPort, p.DstPort)
	}
	if p.DNSQuery != "" {
		fmt.Printf("  DNS=%s", p.DNSQuery)
	}
	if p.HTTPMethod != "" {
		fmt.Printf("  HTTP %s %s", p.HTTPMethod, p.HTTPHost)
	}
	fmt.Println()
}
