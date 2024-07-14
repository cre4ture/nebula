package port_forwarder

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/service"
	"golang.org/x/sync/errgroup"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
)

type PortTunnelOutgoingUdp struct {
	l                     *logrus.Logger
	tunService            *service.Service
	localUdpListenAddr    *net.UDPAddr
	remoteUdpAddr         *net.UDPAddr
	localListenConnection *net.UDPConn
}

type PortTunnelOutgoingTcp struct {
	l                     *logrus.Logger
	tunService            *service.Service
	localTcpListenAddr    *net.TCPAddr
	localListenConnection *net.TCPListener
	remoteTcpAddr         *net.TCPAddr
}

type PortTunnelIngoingUdp struct {
	l                     *logrus.Logger
	tunService            *service.Service
	localUdpListenAddr    *net.UDPAddr
	remoteUdpAddr         *net.UDPAddr
	localListenConnection *net.UDPConn
}

type PortTunnelIngoingTcp struct {
	l                       *logrus.Logger
	tunService              *service.Service
	cfg                     tunnelConfigIngoing
	outsideListenConnection net.Listener
}

type tunnelConfigOutgoing struct {
	localListen   string
	remoteConnect string
}

type tunnelConfigIngoing struct {
	port                uint32
	forwardLocalAddress string
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

func (pfService *PortForwardingService) readOutgoingForwardingRulesFromConfig(c *config.C, protocol string) ([]tunnelConfigOutgoing, error) {
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

func (pfService *PortForwardingService) readIngoingForwardingRulesFromConfig(c *config.C, protocol string) ([]tunnelConfigIngoing, error) {
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
		localUdpListenAddr:    localUdpListenAddr,
		remoteUdpAddr:         remoteUdpAddr,
		localListenConnection: localListenConnection,
	}

	go tunnel.listenLocalPort()

	return tunnel, nil
}

func setupPortTunnelUdpIn(
	tunService *service.Service,
	cfg tunnelConfigIngoing,
	l *logrus.Logger,
) (*PortTunnelIngoingUdp, error) {
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
		localUdpListenAddr:    localUdpListenAddr,
		remoteUdpAddr:         remoteUdpAddr,
		localListenConnection: localListenConnection,
	}

	go tunnel.listenLocalPort()

	return tunnel, nil
}

func (pt *PortTunnelOutgoingUdp) listenLocalPort() error {
	outsideReaderGroup := errgroup.Group{}
	outsidePortReaders := make(map[string]interface{})
	remoteConnections := make(map[string]*gonet.UDPConn)
	var buf [512 * 1024]byte
	for {
		pt.l.Debug("listening on local UDP port ...")
		n, localSourceAddr, err := pt.localListenConnection.ReadFromUDP(buf[0:])
		if err != nil {
			fmt.Println(err)
			return err
		}

		pt.l.Debugf("handling message from local UDP port: %v", localSourceAddr)

		remoteConnection, ok := remoteConnections[localSourceAddr.String()]
		if !ok {
			newRemoteConn, err := pt.tunService.DialUDP(pt.remoteUdpAddr.AddrPort().String())
			if err != nil {
				return err
			}
			remoteConnection = newRemoteConn
			remoteConnections[localSourceAddr.String()] = newRemoteConn
		}

		remoteConnection.Write(buf[:n])

		pt.l.Debugf("send message from %+v, to: %+v, payload-size: %d",
			localSourceAddr, pt.remoteUdpAddr, n)

		_, ok = outsidePortReaders[remoteConnection.LocalAddr().String()]
		if !ok {
			outsideReaderGroup.Go(func() error {
				myLocalSourceAddr := localSourceAddr
				remoteConnection.SetDeadline(time.Time{})
				empty_buf := make([]byte, 0)
				buf := make([]byte, 2*(1<<16))
				for {
					n, err = remoteConnection.Read(buf)
					if n == 0 && (err != nil) {
						pt.l.Debugf("finish reading from UDP remote. read failed: err: %v", err)
						return err
					}

					n, _, err = pt.localListenConnection.WriteMsgUDP(
						buf[:n], empty_buf, myLocalSourceAddr)
					if n == 0 && (err != nil) {
						pt.l.Debugf("finish reading from UDP remote. local write failed: err: %v", err)
						return err
					}
				}
			})
		}
	}
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
		localTcpListenAddr:    localTcpListenAddr,
		localListenConnection: localListenPort,
		remoteTcpAddr:         remoteTcpAddr,
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
		pt.l.Infof("Closed TCP client connection. Err: %v", err)
	}
}

func (pt *PortTunnelOutgoingTcp) handleClientConnection_intern(localConnection net.Conn) error {

	remoteConnection, err := pt.tunService.DialContext(context.Background(), "tcp", pt.remoteTcpAddr.String())
	if err != nil {
		return err
	}
	return handleClientConnection_generic(pt.l, localConnection, remoteConnection)
}

func (pt *PortTunnelIngoingTcp) handleClientConnection(localConnection net.Conn) {
	err := pt.handleClientConnection_intern(localConnection)
	if err != nil {
		pt.l.Infof("Closed TCP client connection. Err: %v", err)
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

	return handleClientConnection_generic(pt.l, outsideConnection, localConnection)
}

func handleClientConnection_generic(l *logrus.Logger, connA, connB net.Conn) error {

	dataTransferCtx, cancel := context.WithCancel(context.Background())

	dataTransferHandler := func(from, to net.Conn) error {

		defer from.Close()
		defer to.Close()

		// no write timeout
		to.SetWriteDeadline(time.Time{})
		from.SetReadDeadline(time.Time{})
		buf := make([]byte, 1)
		for {
			select {
			case <-dataTransferCtx.Done():
				return nil
			default:
			}

			// short read timeout to be able to forward also short packages
			//from.SetReadDeadline(time.Now().Add(time.Millisecond * 3))
			n, err := from.Read(buf)
			if n == 0 && (err != nil) {
				l.Infof("reading from from-connection failed: %v", err)
				cancel()
				return err
			}
			for i := 0; i < n; {
				n, err = to.Write(buf[i:n])
				if err != nil {
					l.Infof("writing to to-connection failed: %v", err)
					cancel()
					return err
				}
				i += n
			}
		}
	}

	errGroup := errgroup.Group{}

	errGroup.Go(func() error { return dataTransferHandler(connA, connB) })
	errGroup.Go(func() error { return dataTransferHandler(connB, connA) })

	return errGroup.Wait()
}

func (t *PortForwardingService) Activate() error {

	t.portTunnelsUdpOutgoing = make(map[uint32]*PortTunnelOutgoingUdp)
	for id, config := range t.configPortTunnelsUdpOutgoing {
		tunnel, err := setupPortTunnelUdpOut(t.tunService, config, t.l)
		if err != nil {
			t.l.Errorf("failed to setup UDP-out port tunnel(%d): %+v", id, config)
		}
		t.portTunnelsUdpOutgoing[uint32(tunnel.localUdpListenAddr.Port)] = tunnel
	}

	t.portTunnelsTcpOutgoing = make(map[uint32]*PortTunnelOutgoingTcp)
	for id, config := range t.configPortTunnelsTcpOutgoing {
		tunnel, err := setupPortTunnelTcpOut(t.tunService, config, t.l)
		if err != nil {
			t.l.Errorf("failed to setup TCP-out port tunnel(%d): %+v", id, config)
		}
		t.portTunnelsTcpOutgoing[uint32(tunnel.localTcpListenAddr.Port)] = tunnel
	}

	t.portTunnelsUdpIngoing = make(map[uint32]*PortTunnelIngoingUdp)
	for id, config := range t.configPortTunnelsUdpIngoing {
		tunnel, err := setupPortTunnelUdpIn(t.tunService, config, t.l)
		if err != nil {
			t.l.Errorf("failed to setup UDP-in port tunnel(%d): %+v", id, config)
		}
		t.portTunnelsUdpOutgoing[uint32(tunnel.localUdpListenAddr.Port)] = tunnel
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
