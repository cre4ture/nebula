package port_forwarder

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/service"
	"golang.org/x/sync/errgroup"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
)

type tunnelConfigOutgoing struct {
	localListen   string
	remoteConnect string
}

type tunnelConfigIngoing struct {
	port                uint32
	forwardLocalAddress string
}

type TimeoutCounter struct {
	counter   atomic.Uint32
	threshold uint32
}

func NewTimeoutCounter(threshold uint32) TimeoutCounter {
	return TimeoutCounter{
		counter:   atomic.Uint32{},
		threshold: threshold,
	}
}

func (tc *TimeoutCounter) Increment(step uint32) bool {
	tc.counter.Add(step)
	return tc.IsTimeout()
}

func (tc *TimeoutCounter) Reset() {
	tc.counter.Store(0)
}

func (tc *TimeoutCounter) IsTimeout() bool {
	return tc.counter.Load() > tc.threshold
}

type TimedConnection[C any] struct {
	connection      C
	timeout_counter TimeoutCounter
}

// use UDP timeout of 300 seconds according to
// https://support.goto.com/connect/help/what-are-the-recommended-nat-keep-alive-settings
var UDP_CONNECTION_TIMEOUT_SECONDS uint32 = 300

type udpConnInterface interface {
	WriteTo(b []byte, addr net.Addr) (int, error)
}

func handleUdpDestinationPortReading[destConn net.Conn, srcConn udpConnInterface](
	l *logrus.Logger,
	connection_name string,
	closedConnections *chan string,
	sourceAddr net.Addr,
	destConnection *TimedConnection[destConn],
	localListenConnection srcConn,
) error {
	// net.Conn is thread-safe according to: https://pkg.go.dev/net#Conn
	// no need for remoteConnection to protect by mutex

	defer func() { (*closedConnections) <- sourceAddr.String() }()

	buf := make([]byte, 2*(1<<16))
	for {
		destConnection.connection.SetDeadline(time.Now().Add(time.Second * 10))
		l.Debugf("UDP connection %s - begin read", connection_name)
		n, err := destConnection.connection.Read(buf)
		if n == 0 {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				l.Debugf("UDP connection %s - timeout tick", connection_name)
				if destConnection.timeout_counter.Increment(10) {
					l.Debugf("UDP connection %s closed due to timeout", connection_name)
					return nil
				}
				continue
			} else {
				l.Debugf("finish reading from UDP dest %s. read failed: err: %v", connection_name, err)
				return err
			}
		}

		destConnection.timeout_counter.Reset()
		l.Debugf("UDP connection %s - read success: %d, sending to %s", connection_name, n, sourceAddr.String())
		n, err = localListenConnection.WriteTo(buf[:n], sourceAddr)
		if n == 0 && (err != nil) {
			l.Debugf("finish reading from UDP dest %s. local write failed: err: %v", connection_name, err)
			return err
		}
	}
}

func handleClosedConnections[C any](
	l *logrus.Logger,
	closedConnections *chan string,
	portReaders *map[string]bool,
	remoteConnections *map[string]*TimedConnection[C],
) {
cleanup:
	for {
		select {
		case closedOne := <-(*closedConnections):
			l.Debugf("closing connection to %s", closedOne)
			delete(*remoteConnections, closedOne)
			delete(*portReaders, closedOne)
		default:
			break cleanup
		}
	}
}

type PortTunnelOutgoingUdp struct {
	l          *logrus.Logger
	tunService *service.Service
	cfg        tunnelConfigOutgoing
	// net.Conn is thread-safe according to: https://pkg.go.dev/net#Conn
	// no need for localListenConnection to protect by mutex
	localListenConnection *net.UDPConn
}

func setupPortTunnelUdpOut(
	tunService *service.Service,
	cfg tunnelConfigOutgoing,
	l *logrus.Logger,
) (*PortTunnelOutgoingUdp, error) {
	localUdpListenAddr, err := net.ResolveUDPAddr("udp", cfg.localListen)
	if err != nil {
		return nil, err
	}
	remoteUdpAddr, err := net.ResolveUDPAddr("udp", cfg.remoteConnect)
	if err != nil {
		return nil, err
	}

	localListenConnection, err := net.ListenUDP("udp", localUdpListenAddr)
	if err != nil {
		return nil, err
	}

	l.Infof("UDP port tunnel to '%v': listening on local UDP addr: '%v'",
		remoteUdpAddr, localUdpListenAddr)

	tunnel := &PortTunnelOutgoingUdp{
		l:                     l,
		tunService:            tunService,
		cfg:                   cfg,
		localListenConnection: localListenConnection,
	}

	go tunnel.listenLocalPort()

	return tunnel, nil
}

func (pt *PortTunnelOutgoingUdp) listenLocalPort() error {
	outsideReaderGroup := errgroup.Group{}
	outsidePortReaders := make(map[string]bool)
	remoteConnections := make(map[string]*TimedConnection[*gonet.UDPConn])
	closedConnections := make(chan string)
	var buf [512 * 1024]byte
	for {
		handleClosedConnections(pt.l, &closedConnections, &outsidePortReaders, &remoteConnections)

		pt.l.Debug("listening on local UDP port ...")
		n, localSourceAddr, err := pt.localListenConnection.ReadFromUDP(buf[0:])
		if err != nil {
			fmt.Println(err)
			return err
		}

		pt.l.Debugf("handling message from local UDP port: %v", localSourceAddr)

		remoteConnection, ok := remoteConnections[localSourceAddr.String()]
		if !ok {
			newRemoteConn, err := pt.tunService.DialUDP(pt.cfg.remoteConnect)
			if err != nil {
				return err
			}
			remoteConnection = &TimedConnection[*gonet.UDPConn]{
				connection:      newRemoteConn,
				timeout_counter: NewTimeoutCounter(UDP_CONNECTION_TIMEOUT_SECONDS),
			}
			remoteConnections[localSourceAddr.String()] = remoteConnection
		}

		pt.l.Debugf("send message from %s, to: %s, payload-size: %d",
			localSourceAddr.String(), remoteConnection.connection.RemoteAddr().String(), n)

		remoteConnection.timeout_counter.Reset()
		remoteConnection.connection.Write(buf[:n])

		_, ok = outsidePortReaders[localSourceAddr.String()]
		if !ok {
			pt.l.Debugf("start new reader goroutine %s, to: %s",
				localSourceAddr.String(), remoteConnection.connection.RemoteAddr().String())

			outsidePortReaders[localSourceAddr.String()] = true
			outsideReaderGroup.Go(func() error {
				return handleUdpDestinationPortReading(
					pt.l, "inside dest", &closedConnections, localSourceAddr,
					remoteConnection, pt.localListenConnection)
			})
		}
	}
}

type PortTunnelIngoingUdp struct {
	l                       *logrus.Logger
	tunService              *service.Service
	cfg                     tunnelConfigIngoing
	outsideListenConnection *gonet.UDPConn
}

func setupPortTunnelUdpIn(
	tunService *service.Service,
	cfg tunnelConfigIngoing,
	l *logrus.Logger,
) (*PortTunnelIngoingUdp, error) {

	conn, err := tunService.ListenUDP(fmt.Sprintf(":%d", cfg.port))
	if err != nil {
		return nil, err
	}

	l.Infof("UDP port tunnel to '%v': listening on outside UDP addr: ':%d'",
		cfg.forwardLocalAddress, cfg.port)

	tunnel := &PortTunnelIngoingUdp{
		l:                       l,
		tunService:              tunService,
		cfg:                     cfg,
		outsideListenConnection: conn,
	}

	go tunnel.listenLocalOutsidePort()

	return tunnel, nil
}

func (pt *PortTunnelIngoingUdp) listenLocalOutsidePort() error {
	insideReaderGroup := errgroup.Group{}
	insidePortReaders := make(map[string]bool)
	remoteConnections := make(map[string]*TimedConnection[*net.UDPConn])
	closedConnections := make(chan string)
	fwdAddr, err := net.ResolveUDPAddr("udp", pt.cfg.forwardLocalAddress)
	if err != nil {
		return err
	}

	var buf [512 * 1024]byte
	for {
		handleClosedConnections(pt.l, &closedConnections, &insidePortReaders, &remoteConnections)

		pt.l.Debug("listening on local outside UDP port ...")
		n, outsideSourceAddr, err := pt.outsideListenConnection.ReadFrom(buf[0:])
		if err != nil {
			fmt.Println(err)
			return err
		}

		pt.l.Debugf("handling message from local outside UDP port: %v", outsideSourceAddr)

		remoteConnection, ok := remoteConnections[outsideSourceAddr.String()]
		if !ok {
			newRemoteConn, err := net.DialUDP("udp", nil, fwdAddr)
			if err != nil {
				return err
			}
			remoteConnection = &TimedConnection[*net.UDPConn]{
				connection:      newRemoteConn,
				timeout_counter: NewTimeoutCounter(UDP_CONNECTION_TIMEOUT_SECONDS),
			}
			remoteConnections[outsideSourceAddr.String()] = remoteConnection
		}

		remoteConnection.connection.Write(buf[:n])
		remoteConnection.timeout_counter.Reset()

		pt.l.Debugf("send message from %+v, to: %+v, payload-size: %d",
			outsideSourceAddr, remoteConnection, n)

		_, ok = insidePortReaders[outsideSourceAddr.String()]
		if !ok {
			insideReaderGroup.Go(func() error {
				return handleUdpDestinationPortReading(
					pt.l, "outside dest", &closedConnections, outsideSourceAddr,
					remoteConnection, pt.outsideListenConnection)
			})
		}
	}
}

type PortTunnelOutgoingTcp struct {
	l                     *logrus.Logger
	tunService            *service.Service
	cfg                   tunnelConfigOutgoing
	localListenConnection *net.TCPListener
}

func setupPortTunnelTcpOut(
	tunService *service.Service,
	cf tunnelConfigOutgoing,
	l *logrus.Logger,
) (*PortTunnelOutgoingTcp, error) {
	localTcpListenAddr, err := net.ResolveTCPAddr("tcp", cf.localListen)
	if err != nil {
		return nil, err
	}
	remoteTcpAddr, err := net.ResolveTCPAddr("tcp", cf.remoteConnect)
	if err != nil {
		return nil, err
	}
	localListenPort, err := net.ListenTCP("tcp", localTcpListenAddr)
	if err != nil {
		return nil, err
	}

	l.Infof("TCP port tunnel to '%v': listening on local TCP addr: '%v'",
		remoteTcpAddr, localTcpListenAddr)

	tunnel := &PortTunnelOutgoingTcp{
		l:                     l,
		tunService:            tunService,
		cfg:                   cf,
		localListenConnection: localListenPort,
	}

	go tunnel.acceptOnLocalListenPort()

	return tunnel, nil
}

func (pt *PortTunnelOutgoingTcp) acceptOnLocalListenPort() error {
	for {
		pt.l.Debug("listening on local TCP port ...")
		connection, err := pt.localListenConnection.AcceptTCP()
		if err != nil {
			fmt.Println(err)
			return err
		}

		pt.l.Debugf("accept TCP connect from local TCP port: %v", connection.RemoteAddr())

		go pt.handleClientConnection(connection)
	}
}

func (pt *PortTunnelOutgoingTcp) handleClientConnection(localConnection *net.TCPConn) {
	err := pt.handleClientConnection_intern(localConnection)
	if err != nil {
		pt.l.Debugf("Closed TCP client connection %s. Err: %v",
			localConnection.LocalAddr().String(), err)
	}
}

func (pt *PortTunnelOutgoingTcp) handleClientConnection_intern(localConnection net.Conn) error {

	remoteConnection, err := pt.tunService.DialContext(context.Background(), "tcp", pt.cfg.remoteConnect)
	if err != nil {
		return err
	}
	return handleTcpClientConnection_generic(pt.l, localConnection, remoteConnection)
}

func handleTcpClientConnection_generic(l *logrus.Logger, connA, connB net.Conn) error {

	dataTransferCtx, cancel := context.WithCancel(context.Background())

	dataTransferHandler := func(from, to net.Conn) error {

		name := fmt.Sprintf("%s -> %s", from.LocalAddr().String(), to.LocalAddr().String())

		defer from.Close()
		defer to.Close()
		defer cancel()
		// give communication in opposite direction time to finish as well
		defer time.Sleep(time.Millisecond * 300)

		// no write/read timeout
		to.SetDeadline(time.Time{})
		from.SetDeadline(time.Time{})
		buf := make([]byte, 1*(1<<20))
		for {
			select {
			case <-dataTransferCtx.Done():
				return nil
			default:
			}

			rn, r_err := from.Read(buf)
			l.Tracef("%s read(%d), err: %v", name, rn, r_err)
			for i := 0; i < rn; {
				wn, w_err := to.Write(buf[i:rn])
				if w_err != nil {
					l.Debugf("%s writing(%d) to to-connection failed: %v", name, rn, w_err)
					return w_err
				}
				i += wn
			}
			if r_err != nil {
				l.Debugf("%s reading(%d) from from-connection failed: %v", name, rn, r_err)
				return r_err
			}
		}
	}

	errGroup := errgroup.Group{}

	errGroup.Go(func() error { return dataTransferHandler(connA, connB) })
	errGroup.Go(func() error { return dataTransferHandler(connB, connA) })

	return errGroup.Wait()
}

type PortTunnelIngoingTcp struct {
	l                       *logrus.Logger
	tunService              *service.Service
	cfg                     tunnelConfigIngoing
	outsideListenConnection net.Listener
}

func setupPortTunnelTcpIn(
	tunService *service.Service,
	cf tunnelConfigIngoing,
	l *logrus.Logger,
) (*PortTunnelIngoingTcp, error) {

	listener, err := tunService.Listen("tcp", fmt.Sprintf(":%d", cf.port))
	if err != nil {
		return nil, err
	}

	l.Infof("TCP port tunnel to '%v': listening on local, outside TCP addr: ':%d'",
		cf.forwardLocalAddress, cf.port)

	tunnel := &PortTunnelIngoingTcp{
		l:                       l,
		tunService:              tunService,
		cfg:                     cf,
		outsideListenConnection: listener,
	}

	go tunnel.acceptOnOutsideListenPort()

	return tunnel, nil
}

func (pt *PortTunnelIngoingTcp) acceptOnOutsideListenPort() error {
	for {
		pt.l.Debug("listening on outside TCP port ...")
		connection, err := pt.outsideListenConnection.Accept()
		if err != nil {
			fmt.Println(err)
			return err
		}

		pt.l.Debugf("accept TCP connect from outside TCP port: %v", connection.RemoteAddr())

		go pt.handleClientConnection(connection)
	}
}

func (pt *PortTunnelIngoingTcp) handleClientConnection(localConnection net.Conn) {
	err := pt.handleClientConnection_intern(localConnection)
	if err != nil {
		pt.l.Debugf("Closed TCP client connection %s. Err: %v",
			localConnection.LocalAddr().String(), err)
	}
}

func (pt *PortTunnelIngoingTcp) handleClientConnection_intern(outsideConnection net.Conn) error {

	fwdAddr, err := net.ResolveTCPAddr("tcp", pt.cfg.forwardLocalAddress)
	if err != nil {
		return err
	}

	localConnection, err := net.DialTCP("tcp", nil, fwdAddr)
	if err != nil {
		return err
	}

	return handleTcpClientConnection_generic(pt.l, outsideConnection, localConnection)
}

type PortForwardingService struct {
	l          *logrus.Logger
	tunService *service.Service

	configPortTunnelsUdpOutgoing []tunnelConfigOutgoing
	configPortTunnelsTcpOutgoing []tunnelConfigOutgoing
	configPortTunnelsUdpIngoing  []tunnelConfigIngoing
	configPortTunnelsTcpIngoing  []tunnelConfigIngoing

	portTunnelsUdpOutgoing map[uint32]*PortTunnelOutgoingUdp
	portTunnelsTcpOutgoing map[uint32]*PortTunnelOutgoingTcp
	portTunnelsUdpIngoing  map[uint32]*PortTunnelIngoingUdp
	portTunnelsTcpIngoing  map[uint32]*PortTunnelIngoingTcp
}

func ConstructFromConfig(
	tunService *service.Service,
	l *logrus.Logger,
	c *config.C,
) (*PortForwardingService, error) {

	pfService := &PortForwardingService{
		l:          l,
		tunService: tunService,
	}

	var err error
	pfService.configPortTunnelsUdpOutgoing, err = pfService.readOutgoingForwardingRulesFromConfig(c, "udp")
	if err != nil {
		return nil, err
	}

	pfService.configPortTunnelsTcpOutgoing, err = pfService.readOutgoingForwardingRulesFromConfig(c, "tcp")
	if err != nil {
		return nil, err
	}

	pfService.configPortTunnelsUdpIngoing, err = pfService.readIngoingForwardingRulesFromConfig(c, "udp")
	if err != nil {
		return nil, err
	}

	pfService.configPortTunnelsTcpIngoing, err = pfService.readIngoingForwardingRulesFromConfig(c, "tcp")
	if err != nil {
		return nil, err
	}

	return pfService, nil
}

func (t *PortForwardingService) Activate() error {

	t.portTunnelsUdpOutgoing = make(map[uint32]*PortTunnelOutgoingUdp)
	for id, config := range t.configPortTunnelsUdpOutgoing {
		tunnel, err := setupPortTunnelUdpOut(t.tunService, config, t.l)
		if err != nil {
			t.l.Errorf("failed to setup UDP-out port tunnel(%d): %+v", id, config)
		}
		t.portTunnelsUdpOutgoing[uint32(id)] = tunnel
	}

	t.portTunnelsTcpOutgoing = make(map[uint32]*PortTunnelOutgoingTcp)
	for id, config := range t.configPortTunnelsTcpOutgoing {
		tunnel, err := setupPortTunnelTcpOut(t.tunService, config, t.l)
		if err != nil {
			t.l.Errorf("failed to setup TCP-out port tunnel(%d): %+v", id, config)
		}
		t.portTunnelsTcpOutgoing[uint32(id)] = tunnel
	}

	t.portTunnelsUdpIngoing = make(map[uint32]*PortTunnelIngoingUdp)
	for id, config := range t.configPortTunnelsUdpIngoing {
		tunnel, err := setupPortTunnelUdpIn(t.tunService, config, t.l)
		if err != nil {
			t.l.Errorf("failed to setup UDP-in port tunnel(%d): %+v", id, config)
		}
		t.portTunnelsUdpIngoing[uint32(tunnel.cfg.port)] = tunnel
	}

	t.portTunnelsTcpIngoing = make(map[uint32]*PortTunnelIngoingTcp)
	for id, config := range t.configPortTunnelsTcpIngoing {
		tunnel, err := setupPortTunnelTcpIn(t.tunService, config, t.l)
		if err != nil {
			t.l.Errorf("failed to setup TCP-in port tunnel(%d): %+v", id, config)
		}
		t.portTunnelsTcpIngoing[uint32(tunnel.cfg.port)] = tunnel
	}

	return nil
}

func (pfService *PortForwardingService) readOutgoingForwardingRulesFromConfig(
	c *config.C, protocol string,
) ([]tunnelConfigOutgoing, error) {
	table := "port_tunnel.outgoing." + protocol
	out := make([]tunnelConfigOutgoing, 0)

	r := c.Get(table)
	if r == nil {
		return nil, nil
	}

	rs, ok := r.([]interface{})
	if !ok {
		return nil, fmt.Errorf("%s failed to parse, should be an array of port tunnels", table)
	}

	for i, t := range rs {
		portTunnelConfig, err := convertToTunnelConfigOutgoing(pfService.l, t)
		if err != nil {
			return nil, fmt.Errorf("%s port tunnel #%v; %s", table, i, err)
		}
		out = append(out, portTunnelConfig)
	}

	return out, nil
}

func (pfService *PortForwardingService) readIngoingForwardingRulesFromConfig(
	c *config.C, protocol string,
) ([]tunnelConfigIngoing, error) {
	table := "port_tunnel.ingoing." + protocol
	out := make([]tunnelConfigIngoing, 0)

	r := c.Get(table)
	if r == nil {
		return nil, nil
	}

	rs, ok := r.([]interface{})
	if !ok {
		return nil, fmt.Errorf("%s failed to parse, should be an array of port tunnels", table)
	}

	for i, t := range rs {
		portTunnelConfig, err := convertToTunnelConfigIngoing(pfService.l, t)
		if err != nil {
			return nil, fmt.Errorf("%s port tunnel #%v; %s", table, i, err)
		}
		out = append(out, portTunnelConfig)
	}

	return out, nil
}

func convertToTunnelConfigOutgoing(_ *logrus.Logger, p interface{}) (tunnelConfigOutgoing, error) {
	fwd_tunnel := tunnelConfigOutgoing{}

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

	fwd_tunnel.localListen = toString("local_address", m)
	fwd_tunnel.remoteConnect = toString("remote_address", m)

	return fwd_tunnel, nil
}

func convertToTunnelConfigIngoing(_ *logrus.Logger, p interface{}) (tunnelConfigIngoing, error) {
	fwd_tunnel := tunnelConfigIngoing{}

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

	v, err := strconv.ParseUint(toString("port", m), 10, 32)
	if err != nil {
		return fwd_tunnel, err
	}
	fwd_tunnel.port = uint32(v)
	fwd_tunnel.forwardLocalAddress = toString("forward_address", m)

	return fwd_tunnel, nil
}
