package overlay

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"slices"
	"strings"

	"github.com/rcrowley/go-metrics"
	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/iputil"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"

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

type PortTunnelTcp struct {
	l                        *logrus.Logger
	ownIpInOverlayNet        net.IP
	send                     func([]byte)
	localTcpListenAddr       *net.TCPAddr
	listenConnection         *net.TCPListener
	remoteTcpAddr            *net.TCPAddr
	outsideClientConnections map[uint32]chan []byte
	stack                    *stack.Stack
	linkEP                   *channel.Endpoint
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

	// local listening initialized

	addr := tcpip.AddrFromSlice(ownIpInOverlayNet)

	// Create the stack with ipv4 and tcp protocols, then add a channel-based
	// NIC and ipv4 address.
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{func(s *stack.Stack) stack.NetworkProtocol {
			return ipv4.NewProtocol(s)
		}},
		TransportProtocols: []stack.TransportProtocolFactory{func(s *stack.Stack) stack.TransportProtocol {
			return tcp.NewProtocol(s)
		}},
	})

	// this link address should be irrelevant as we have UDP as link layer
	linkAddress, err := tcpip.ParseMACAddress("aa:bb:cc:dd:ee:ff")
	if err != nil {
		return nil, err
	}

	linkEP := channel.New(100, 9001, linkAddress) // TODO
	if err := s.CreateNIC(1, linkEP); err != nil {
		log.Fatal(err)
	}

	if err := s.AddProtocolAddress(1,
		tcpip.ProtocolAddress{
			Protocol: ipv4.ProtocolNumber,
			AddressWithPrefix: tcpip.AddressWithPrefix{
				Address:   addr,
				PrefixLen: 24, // TODO
			},
		},
		stack.AddressProperties{},
	); err != nil {
		log.Fatal(err)
	}

	// Add default route.
	s.SetRouteTable([]tcpip.Route{
		{
			Destination: header.IPv4EmptySubnet,
			NIC:         1,
		},
	})

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
		stack:                    s,
		linkEP:                   linkEP,
	}, nil
}

func (pt *PortTunnelTcp) handleResponse(b []byte) error {
	if pt.linkEP != nil {
		pt.linkEP.InjectInbound(
			tcpip.NetworkProtocolNumber(2048),
			stack.NewPacketBuffer()
		) // TODO
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

		go pt.handleClientConnection(connection)
	}
}

func (pt *PortTunnelTcp) handleClientConnection(localConnection *net.TCPConn) error {

	// Create TCP endpoint.
	var wq waiter.Queue
	remoteConnection, e := pt.stack.NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &wq)
	if e != nil {
		log.Fatal(e)
		return errors.New(e.String())
	}

	remote := tcpip.FullAddress{
		NIC:  1,
		Addr: tcpip.AddrFromSlice(pt.remoteTcpAddr.IP),
		Port: uint16(pt.remoteTcpAddr.Port),
	}

	{
		// Issue connect request and wait for it to complete.
		waitEntry, notifyCh := waiter.NewChannelEntry(waiter.EventOut)
		wq.EventRegister(&waitEntry)
		terr := remoteConnection.Connect(remote)
		if (terr == &tcpip.ErrConnectStarted{}) {
			fmt.Println("Connect is pending...")
			<-notifyCh
			terr = remoteConnection.SocketOptions().GetLastError()
		}
		wq.EventUnregister(&waitEntry)

		if terr != nil {
			log.Fatal("Unable to connect: ", terr)
			return errors.New(fmt.Sprintf("Unable to connect: ", terr))
		}

		fmt.Println("Connected")
	}

	// Start the writer in its own goroutine.
	writerCompletedCh := make(chan struct{})
	go writer(writerCompletedCh, localConnection, remoteConnection)

	// Read data and write to standard output until the peer closes the
	// connection from its side.
	waitEntry, notifyCh := waiter.NewChannelEntry(waiter.EventIn)
	wq.EventRegister(&waitEntry)

	var buf bytes.Buffer
	for {
		_, err := remoteConnection.Read(&buf, tcpip.ReadOptions{})
		if err != nil {
			if (err == &tcpip.ErrClosedForReceive{}) {
				break
			}

			if (err == &tcpip.ErrWouldBlock{}) {
				<-notifyCh
				continue
			}

			log.Fatal("Read() failed:", err)
		}

		_, e := localConnection.Write(buf.Bytes())
		if e != nil {
			log.Fatal(e)
			return e
		}
	}
	wq.EventUnregister(&waitEntry)

	// The reader has completed. Now wait for the writer as well.
	<-writerCompletedCh

	remoteConnection.Close()
	return nil
}

func writer(ch chan struct{}, localConnection *net.TCPConn, remoteConnection tcpip.Endpoint) {
	defer func() {
		remoteConnection.Shutdown(tcpip.ShutdownWrite)
		close(ch)
	}()

	buf := make([]byte, 512*1024)
	for {
		n, err := localConnection.Read(buf)
		if err != nil {
			return
		}

		reader := bytes.NewReader(buf[:n])
		for reader.Len() > 0 {
			_, werr := remoteConnection.Write(reader, tcpip.WriteOptions{})
			if werr != nil {
				fmt.Println("Write failed:", werr)
				return
			}
		}
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
