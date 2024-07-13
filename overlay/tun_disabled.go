package overlay

import (
	"fmt"
	"io"
	"net"
	"slices"
	"strings"

	"github.com/rcrowley/go-metrics"
	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/iputil"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type PortTunnelUdp struct {
	l                  *logrus.Logger
	ownIpInOverlayNet  net.IP
	send               func([]byte)
	localUdpListenAddr *net.UDPAddr
	connection         *net.UDPConn
	remoteUdpAddr      *net.UDPAddr
	localSourceAddr    *net.UDPAddr
}

func setupPortTunnelUdp(
	localListeningAddress string,
	remoteDestinationAddress string,
	ownIpInOverlayNet net.IP,
	send func([]byte),
	l *logrus.Logger,
) (*PortTunnelUdp, error) {
	localUdpListenAddr, err := net.ResolveUDPAddr("udp", localListeningAddress)
	if err != nil {
		return nil, err
	}
	remoteUdpAddr, err := net.ResolveUDPAddr("udp", remoteDestinationAddress)
	if err != nil {
		return nil, err
	}

	localListenPort, err := net.ListenUDP("udp", localUdpListenAddr)
	if err != nil {
		return nil, err
	}

	l.Infof("UDP port tunnel to '%v': listening on local UDP addr: '%v'",
		remoteUdpAddr, localUdpListenAddr)

	return &PortTunnelUdp{
		l:                  l,
		ownIpInOverlayNet:  ownIpInOverlayNet,
		send:               send,
		localUdpListenAddr: localUdpListenAddr,
		connection:         localListenPort,
		remoteUdpAddr:      remoteUdpAddr,
		localSourceAddr:    nil,
	}, nil
}

func (pt *PortTunnelUdp) handleResponse(b []byte) error {
	if pt.localSourceAddr != nil {
		_, err := pt.connection.WriteToUDP(b, pt.localSourceAddr)
		return err
	}
	return nil
}

func (pt *PortTunnelUdp) listenLocalPort() error {
	var buf [512 * 1024]byte
	for {
		pt.l.Debug("listening on local UDP port ...")
		n, addr, err := pt.connection.ReadFromUDP(buf[0:])
		if err != nil {
			fmt.Println(err)
			return err
		}

		pt.l.Debugf("handling message from local UDP port: %v", addr)

		pt.localSourceAddr = addr

		ipLayer := &layers.IPv4{
			Version:  4,
			TTL:      64,
			SrcIP:    pt.ownIpInOverlayNet,
			DstIP:    pt.remoteUdpAddr.IP,
			Protocol: layers.IPProtocolUDP,
		}
		udpLayer := &layers.UDP{
			SrcPort: layers.UDPPort(pt.localUdpListenAddr.Port),
			DstPort: layers.UDPPort(pt.remoteUdpAddr.Port),
		}
		udpLayer.SetNetworkLayerForChecksum(ipLayer)

		sendBuf := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{
			ComputeChecksums: true,
			FixLengths:       true,
		}
		gopacket.SerializeLayers(sendBuf, opts,
			ipLayer,
			udpLayer,
			gopacket.Payload(buf[0:n]))
		packetData := sendBuf.Bytes()

		pt.send(packetData)

		pt.l.Debugf("send message to: %+v, %+v, payload-size: %d", ipLayer, udpLayer, n)
	}
}

type disabledTun struct {
	read chan []byte
	cidr *net.IPNet

	// Track these metrics since we don't have the tun device to do it for us
	tx metrics.Counter
	rx metrics.Counter
	l  *logrus.Logger

	portTunnelsUdp map[uint32]*PortTunnelUdp
}

func newDisabledTun(cidr *net.IPNet, queueLen int, metricsEnabled bool, l *logrus.Logger) *disabledTun {
	tun := &disabledTun{
		cidr: cidr,
		read: make(chan []byte, queueLen),
		l:    l,
	}

	if metricsEnabled {
		tun.tx = metrics.GetOrRegisterCounter("messages.tx.message", nil)
		tun.rx = metrics.GetOrRegisterCounter("messages.rx.message", nil)
	} else {
		tun.tx = &metrics.NilCounter{}
		tun.rx = &metrics.NilCounter{}
	}

	return tun
}

func (t *disabledTun) Activate() error {

	tunnel, err := setupPortTunnelUdp(
		"127.0.0.1:3399",
		"192.168.100.92:4499",
		t.cidr.IP, func(out []byte) {
			t.read <- out
		},
		t.l,
	)
	if err != nil {
		return err
	}

	t.portTunnelsUdp = make(map[uint32]*PortTunnelUdp)
	t.portTunnelsUdp[3399] = tunnel
	go tunnel.listenLocalPort()

	return nil
}

func (*disabledTun) RouteFor(iputil.VpnIp) iputil.VpnIp {
	return 0
}

func (t *disabledTun) Cidr() *net.IPNet {
	return t.cidr
}

func (*disabledTun) Name() string {
	return "disabled"
}

func (t *disabledTun) Read(b []byte) (int, error) {
	r, ok := <-t.read
	if !ok {
		return 0, io.EOF
	}

	if len(r) > len(b) {
		return 0, fmt.Errorf("packet larger than mtu: %d > %d bytes", len(r), len(b))
	}

	t.tx.Inc(1)
	if t.l.Level >= logrus.DebugLevel {
		t.l.WithField("raw", prettyPacket(r)).Debugf("Write payload")
	}

	return copy(b, r), nil
}

func (t *disabledTun) handleICMPEchoRequest(b []byte) bool {
	out := make([]byte, len(b))
	out = iputil.CreateICMPEchoResponse(b, out)
	if out == nil {
		return false
	}

	// attempt to write it, but don't block
	select {
	case t.read <- out:
	default:
		t.l.Debugf("tun_disabled: dropped ICMP Echo Reply response")
	}

	return true
}

func (t *disabledTun) handleDataFromOutsideToTunnelPort(packetData []byte) bool {

	var ip4 layers.IPv4
	var udp layers.UDP
	var payload gopacket.Payload
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeIPv4, &ip4, &udp, &payload)
	decoded := []gopacket.LayerType{}
	if err := parser.DecodeLayers(packetData, &decoded); err != nil {
		t.l.Warnf("Could not decode layers: %v\n", err)
		return false
	}
	t.l.Debugf("decoded layers: %+v", decoded)
	if !slices.Contains(decoded, layers.LayerTypeIPv4) ||
		!slices.Contains(decoded, layers.LayerTypeUDP) {
		t.l.Warnf("Could not decode layers: Missing IPv4 or UDP\n")
		return false
	}
	portTunnel, ok := t.portTunnelsUdp[uint32(udp.DstPort)]
	t.l.Debugf("handle data to tunnel: %+v, %t", portTunnel, ok)
	if ok {
		portTunnel.handleResponse(udp.Payload)
	}
	return ok
}

// from outside to tun "userspace"
func (t *disabledTun) Write(b []byte) (int, error) {
	t.rx.Inc(1)

	// Check for ICMP Echo Request before spending time doing the full parsing
	switch {
	case t.handleICMPEchoRequest(b):
		{
			if t.l.Level >= logrus.DebugLevel {
				t.l.WithField("raw", prettyPacket(b)).Debugf("Disabled tun responded to ICMP Echo Request")
			}
		}
	case t.handleDataFromOutsideToTunnelPort(b):
		{
			if t.l.Level >= logrus.DebugLevel {
				t.l.WithField("raw", prettyPacket(b)).Debugf("Disabled tun handled port tunnel package")
			}
		}
	default:
		if t.l.Level >= logrus.DebugLevel {
			t.l.WithField("raw", prettyPacket(b)).Debugf("Disabled tun received unexpected payload")
		}
	}
	return len(b), nil
}

func (t *disabledTun) NewMultiQueueReader() (io.ReadWriteCloser, error) {
	return t, nil
}

func (t *disabledTun) Close() error {
	if t.read != nil {
		close(t.read)
		t.read = nil
	}
	return nil
}

type prettyPacket []byte

func (p prettyPacket) String() string {
	var s strings.Builder

	for i, b := range p {
		if i > 0 && i%8 == 0 {
			s.WriteString(" ")
		}
		s.WriteString(fmt.Sprintf("%02x ", b))
	}

	return s.String()
}
