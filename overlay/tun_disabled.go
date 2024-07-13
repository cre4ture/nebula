package overlay

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"

	"github.com/rcrowley/go-metrics"
	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/iputil"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"

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

type tcpIpPackageDecoder struct {
	l         *logrus.Logger
	ip4       *layers.IPv4
	tcp       *layers.TCP
	container *gopacket.DecodingLayerContainer
	decoder   *gopacket.DecodingLayerFunc
	decoded   []gopacket.LayerType
}

func constructIp4Decoder(l *logrus.Logger) *tcpIpPackageDecoder {
	ip4 := &layers.IPv4{}
	tcp := &layers.TCP{}
	dlc := gopacket.DecodingLayerContainer(gopacket.DecodingLayerArray(nil))
	dlc = dlc.Put(ip4)
	dlc = dlc.Put(tcp)
	// you may specify some meaningful DecodeFeedback
	decoder := dlc.LayersDecoder(layers.LayerTypeIPv4, gopacket.NilDecodeFeedback)
	decoded := make([]gopacket.LayerType, 0, 20)

	return &tcpIpPackageDecoder{
		l:         l,
		ip4:       ip4,
		tcp:       tcp,
		container: &dlc,
		decoder:   &decoder,
		decoded:   decoded,
	}
}

func (d *tcpIpPackageDecoder) decode(packetData []byte) error {

	lt, err := (*d.decoder)(packetData, &d.decoded)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not decode layers: %v\n", err)
		return err
	}
	if lt != gopacket.LayerTypeZero {
		fmt.Fprintf(os.Stderr, "unknown layer type: %v\n", lt)
		return err
	}
	d.l.Debugf("decoded layers: %+v", d.decoded)
	if !slices.Contains(d.decoded, layers.LayerTypeIPv4) ||
		!slices.Contains(d.decoded, layers.LayerTypeTCP) {
		d.l.Warnf("Could not decode layers: Missing IPv4 or TCP\n")
		return errors.New("failed to decode TCP package")
	}
	return nil
}

type PortTunnelTcp struct {
	l                        *logrus.Logger
	ownIpInOverlayNet        net.IP
	send                     func([]byte)
	localTcpListenAddr       *net.TCPAddr
	listenConnection         *net.TCPListener
	remoteTcpAddr            *net.TCPAddr
	outsideClientConnections map[uint32]chan []byte
	tunDevice                *tun.Device
	tunNet                   *netstack.Net
	device                   *device.Device
}

func setupPortTunnelTcp(
	localListeningAddress string,
	remoteDestinationAddress string,
	ownIpInOverlayNet net.IP,
	send func([]byte),
	l *logrus.Logger,
) (*PortTunnelTcp, error) {
	localTcpListenAddr, err := net.ResolveTCPAddr("tcp", localListeningAddress)
	if err != nil {
		return nil, err
	}
	remoteTcpAddr, err := net.ResolveTCPAddr("tcp", remoteDestinationAddress)
	if err != nil {
		return nil, err
	}

	localListenPort, err := net.ListenTCP("tcp", localTcpListenAddr)
	if err != nil {
		return nil, err
	}

	tun, tnet, err := netstack.CreateNetTUN(
		[]netip.Addr{netip.MustParseAddr(ownIpInOverlayNet.String())},
		[]netip.Addr{},
		1420)
	if err != nil {
		log.Panic(err)
	}
	dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelVerbose, ""))

	l.Infof("TCP port tunnel to '%v': listening on local TCP addr: '%v'",
		remoteTcpAddr, localTcpListenAddr)

	return &PortTunnelTcp{
		l:                        l,
		ownIpInOverlayNet:        ownIpInOverlayNet,
		send:                     send,
		localTcpListenAddr:       localTcpListenAddr,
		listenConnection:         localListenPort,
		remoteTcpAddr:            remoteTcpAddr,
		outsideClientConnections: make(map[uint32]chan []byte),
		tunDevice:                &tun,
		tunNet:                   tnet,
		device:                   dev,
	}, nil
}

func (pt *PortTunnelTcp) handleResponse(b []byte) error {
	if pt.localSourceAddr != nil {
		_, err := pt.listenConnection.WriteToUDP(b, pt.localSourceAddr)
		return err
	}
	return nil
}

func (pt *PortTunnelTcp) listenLocalPort() error {
	for {
		pt.l.Debug("listening on local TCP port ...")
		connection, err := pt.listenConnection.AcceptTCP()
		if err != nil {
			fmt.Println(err)
			return err
		}

		pt.l.Debugf("accept TCP connect from local TCP port: %v", connection.RemoteAddr())

		localTcpAddr, err := net.ResolveTCPAddr("tcp", connection.LocalAddr().String())
		if err != nil {
			return err
		}

		rx_chan := make(chan []byte)
		pt.outsideClientConnections[uint32(localTcpAddr.Port)] = rx_chan

		tcpClientConnection, err := pt.tunNet.DialTCPAddrPort(netip.MustParseAddrPort(pt.remoteTcpAddr.String()))
		if err != nil {
			return err
		}

		go func() {

			buf := make([]byte, 512*1024)
			for {
				n, err := connection.Read(buf)
				if err != nil {
					pt.l.Infof("error: closing TCP connection from local TCP port: %v, err: %v",
						connection.RemoteAddr(), err)
					return
				}

				sendBuf := gopacket.NewSerializeBuffer()
				gopacket.SerializeLayers(sendBuf, opts,
					ipLayer,
					tcpLayer,
					gopacket.Payload(buf[0:n]))
				packetData := sendBuf.Bytes()
				pt.send(packetData)

				pt.l.Debugf("send message to: %+v, %+v, payload-size: %d", ipLayer, tcpLayer, n)
			}
		}()
	}
}

type tunnelConfig struct {
	local  string
	remote string
}

type disabledTun struct {
	read chan []byte
	cidr *net.IPNet

	// Track these metrics since we don't have the tun device to do it for us
	tx metrics.Counter
	rx metrics.Counter
	l  *logrus.Logger

	configPortTunnelsUdp []tunnelConfig
	configPortTunnelsTcp []tunnelConfig

	portTunnelsUdp map[uint32]*PortTunnelUdp
	portTunnelsTcp map[uint32]*PortTunnelTcp
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

func convertToPortTunnelConfig(_ *logrus.Logger, p interface{}) (tunnelConfig, error) {
	fwd_tunnel := tunnelConfig{}

	m, ok := p.(map[interface{}]interface{})
	if !ok {
		return fwd_tunnel, errors.New("could not parse tunnel config")
	}

	toString := func(k string, m map[interface{}]interface{}) string {
		v, ok := m[k]
		if !ok {
			return ""
		}
		return fmt.Sprintf("%v", v)
	}

	fwd_tunnel.local = toString("local_address", m)
	fwd_tunnel.remote = toString("remote_address", m)

	return fwd_tunnel, nil
}

func (tun *disabledTun) readPortTunnelRulesFromConfig(c *config.C, protocol string) ([]tunnelConfig, error) {
	table := "port_tunnel." + protocol
	out := make([]tunnelConfig, 0)

	r := c.Get(table)
	if r == nil {
		return nil, nil
	}

	rs, ok := r.([]interface{})
	if !ok {
		return nil, fmt.Errorf("%s failed to parse, should be an array of port tunnels", table)
	}

	for i, t := range rs {
		portTunnelConfig, err := convertToPortTunnelConfig(tun.l, t)
		if err != nil {
			return nil, fmt.Errorf("%s port tunnel #%v; %s", table, i, err)
		}
		out = append(out, portTunnelConfig)
	}

	return out, nil
}

func (tun *disabledTun) AddPortTunnelRulesFromConfig(c *config.C) error {

	udp, err := tun.readPortTunnelRulesFromConfig(c, "udp")
	if err != nil {
		return err
	}

	tcp, err := tun.readPortTunnelRulesFromConfig(c, "tcp")
	if err != nil {
		return err
	}

	tun.configPortTunnelsUdp = udp
	tun.configPortTunnelsTcp = tcp

	return nil
}

func (t *disabledTun) Activate() error {

	t.portTunnelsUdp = make(map[uint32]*PortTunnelUdp)
	for id, config := range t.configPortTunnelsUdp {
		tunnel, err := setupPortTunnelUdp(
			config.local,
			config.remote,
			t.cidr.IP,
			func(out []byte) {
				t.read <- out
			},
			t.l,
		)
		if err != nil {
			t.l.Errorf("failed to setup UDP port tunnel(%d): %+v", id, config)
		}
		t.portTunnelsUdp[uint32(tunnel.localUdpListenAddr.Port)] = tunnel
		go tunnel.listenLocalPort()
	}

	t.portTunnelsTcp = make(map[uint32]*PortTunnelTcp)
	for id, config := range t.configPortTunnelsTcp {
		tunnel, err := setupPortTunnelTcp(
			config.local,
			config.remote,
			t.cidr.IP,
			func(out []byte) {
				t.read <- out
			},
			t.l,
		)
		if err != nil {
			t.l.Errorf("failed to setup TCP port tunnel(%d): %+v", id, config)
		}
		t.portTunnelsUdp[uint32(tunnel.localUdpListenAddr.Port)] = tunnel
		go tunnel.listenLocalPort()
	}

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
