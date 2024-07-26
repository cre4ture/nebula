package port_forwarder

import (
	"context"
	"fmt"
	"net"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/service"
	"golang.org/x/sync/errgroup"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
)

type forwardConfigOutgoing struct {
	localListen   string
	remoteConnect string
}

type forwardConfigIncoming struct {
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

type PortForwardingOutgoingUdp struct {
	l          *logrus.Logger
	tunService *service.Service
	cfg        forwardConfigOutgoing
	// net.Conn is thread-safe according to: https://pkg.go.dev/net#Conn
	// no need for localListenConnection to protect by mutex
	localListenConnection *net.UDPConn
}

func setupPortForwardingUdpOut(
	tunService *service.Service,
	cfg forwardConfigOutgoing,
	l *logrus.Logger,
) (*PortForwardingOutgoingUdp, error) {
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

	l.Infof("UDP port forwarding to '%v': listening on local UDP addr: '%v'",
		remoteUdpAddr, localUdpListenAddr)

	portForwarding := &PortForwardingOutgoingUdp{
		l:                     l,
		tunService:            tunService,
		cfg:                   cfg,
		localListenConnection: localListenConnection,
	}

	go portForwarding.listenLocalPort()

	return portForwarding, nil
}

func (pt *PortForwardingOutgoingUdp) listenLocalPort() error {
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

type PortForwardingIncomingUdp struct {
	l                       *logrus.Logger
	tunService              *service.Service
	cfg                     forwardConfigIncoming
	outsideListenConnection *gonet.UDPConn
}

func setupPortForwardingUdpIn(
	tunService *service.Service,
	cfg forwardConfigIncoming,
	l *logrus.Logger,
) (*PortForwardingIncomingUdp, error) {

	conn, err := tunService.ListenUDP(fmt.Sprintf(":%d", cfg.port))
	if err != nil {
		return nil, err
	}

	l.Infof("UDP port forwarding to '%v': listening on outside UDP addr: ':%d'",
		cfg.forwardLocalAddress, cfg.port)

	forwarding := &PortForwardingIncomingUdp{
		l:                       l,
		tunService:              tunService,
		cfg:                     cfg,
		outsideListenConnection: conn,
	}

	go forwarding.listenLocalOutsidePort()

	return forwarding, nil
}

func (pt *PortForwardingIncomingUdp) listenLocalOutsidePort() error {
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
			insidePortReaders[outsideSourceAddr.String()] = true
			insideReaderGroup.Go(func() error {
				return handleUdpDestinationPortReading(
					pt.l, "outside dest", &closedConnections, outsideSourceAddr,
					remoteConnection, pt.outsideListenConnection)
			})
		}
	}
}

type PortForwardingOutgoingTcp struct {
	l                     *logrus.Logger
	tunService            *service.Service
	cfg                   forwardConfigOutgoing
	localListenConnection *net.TCPListener
}

func setupPortForwardingTcpOut(
	tunService *service.Service,
	cf forwardConfigOutgoing,
	l *logrus.Logger,
) (*PortForwardingOutgoingTcp, error) {
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

	l.Infof("TCP port forwarding to '%v': listening on local TCP addr: '%v'",
		remoteTcpAddr, localTcpListenAddr)

	portForwarding := &PortForwardingOutgoingTcp{
		l:                     l,
		tunService:            tunService,
		cfg:                   cf,
		localListenConnection: localListenPort,
	}

	go portForwarding.acceptOnLocalListenPort()

	return portForwarding, nil
}

func (pt *PortForwardingOutgoingTcp) acceptOnLocalListenPort() error {
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

func (pt *PortForwardingOutgoingTcp) handleClientConnection(localConnection *net.TCPConn) {
	err := pt.handleClientConnection_intern(localConnection)
	if err != nil {
		pt.l.Debugf("Closed TCP client connection %s. Err: %v",
			localConnection.LocalAddr().String(), err)
	}
}

func (pt *PortForwardingOutgoingTcp) handleClientConnection_intern(localConnection net.Conn) error {

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

type PortForwardingIncomingTcp struct {
	l                       *logrus.Logger
	tunService              *service.Service
	cfg                     forwardConfigIncoming
	outsideListenConnection net.Listener
}

func setupPortForwardingTcpIn(
	tunService *service.Service,
	cf forwardConfigIncoming,
	l *logrus.Logger,
) (*PortForwardingIncomingTcp, error) {

	listener, err := tunService.Listen("tcp", fmt.Sprintf(":%d", cf.port))
	if err != nil {
		return nil, err
	}

	l.Infof("TCP port forwarding to '%v': listening on local, outside TCP addr: ':%d'",
		cf.forwardLocalAddress, cf.port)

	portForwarding := &PortForwardingIncomingTcp{
		l:                       l,
		tunService:              tunService,
		cfg:                     cf,
		outsideListenConnection: listener,
	}

	go portForwarding.acceptOnOutsideListenPort()

	return portForwarding, nil
}

func (pt *PortForwardingIncomingTcp) acceptOnOutsideListenPort() error {
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

func (pt *PortForwardingIncomingTcp) handleClientConnection(localConnection net.Conn) {
	err := pt.handleClientConnection_intern(localConnection)
	if err != nil {
		pt.l.Debugf("Closed TCP client connection %s. Err: %v",
			localConnection.LocalAddr().String(), err)
	}
}

func (pt *PortForwardingIncomingTcp) handleClientConnection_intern(outsideConnection net.Conn) error {

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

	configPortForwardingsUdpOutgoing []forwardConfigOutgoing
	configPortForwardingsTcpOutgoing []forwardConfigOutgoing
	configPortForwardingsUdpIncoming []forwardConfigIncoming
	configPortForwardingsTcpIncoming []forwardConfigIncoming

	portForwardingsUdpOutgoing map[uint32]*PortForwardingOutgoingUdp
	portForwardingsTcpOutgoing map[uint32]*PortForwardingOutgoingTcp
	portForwardingsUdpIncoming map[uint32]*PortForwardingIncomingUdp
	portForwardingsTcpIncoming map[uint32]*PortForwardingIncomingTcp
}

func (t *PortForwardingService) Activate() error {

	t.portForwardingsUdpOutgoing = make(map[uint32]*PortForwardingOutgoingUdp)
	for id, config := range t.configPortForwardingsUdpOutgoing {
		portForwarding, err := setupPortForwardingUdpOut(t.tunService, config, t.l)
		if err != nil {
			t.l.Errorf("failed to setup UDP-out port forwarding(%d): %+v", id, config)
		}
		t.portForwardingsUdpOutgoing[uint32(id)] = portForwarding
	}

	t.portForwardingsTcpOutgoing = make(map[uint32]*PortForwardingOutgoingTcp)
	for id, config := range t.configPortForwardingsTcpOutgoing {
		portForwarding, err := setupPortForwardingTcpOut(t.tunService, config, t.l)
		if err != nil {
			t.l.Errorf("failed to setup TCP-out port forwarding(%d): %+v", id, config)
		}
		t.portForwardingsTcpOutgoing[uint32(id)] = portForwarding
	}

	t.portForwardingsUdpIncoming = make(map[uint32]*PortForwardingIncomingUdp)
	for id, config := range t.configPortForwardingsUdpIncoming {
		portForwarding, err := setupPortForwardingUdpIn(t.tunService, config, t.l)
		if err != nil {
			t.l.Errorf("failed to setup UDP-in port forwarding(%d): %+v", id, config)
		}
		t.portForwardingsUdpIncoming[uint32(portForwarding.cfg.port)] = portForwarding
	}

	t.portForwardingsTcpIncoming = make(map[uint32]*PortForwardingIncomingTcp)
	for id, config := range t.configPortForwardingsTcpIncoming {
		portForwardings, err := setupPortForwardingTcpIn(t.tunService, config, t.l)
		if err != nil {
			t.l.Errorf("failed to setup TCP-in port forwarding(%d): %+v", id, config)
		}
		t.portForwardingsTcpIncoming[uint32(portForwardings.cfg.port)] = portForwardings
	}

	return nil
}
