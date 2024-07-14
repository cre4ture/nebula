package port_forwarder

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/service"
	"golang.org/x/sync/errgroup"
)

type PortTunnelUdp struct {
	l                     *logrus.Logger
	tunService            *service.Service
	localUdpListenAddr    *net.UDPAddr
	remoteUdpAddr         *net.UDPAddr
	localListenConnection *net.UDPConn
}

type PortTunnelTcp struct {
	l                     *logrus.Logger
	tunService            *service.Service
	localTcpListenAddr    *net.TCPAddr
	localListenConnection *net.TCPListener
	remoteTcpAddr         *net.TCPAddr
}

type tunnelConfig struct {
	local  string
	remote string
}

type PortForwardingService struct {
	l          *logrus.Logger
	tunService *service.Service

	configPortTunnelsUdp []tunnelConfig
	configPortTunnelsTcp []tunnelConfig

	portTunnelsUdp map[uint32]*PortTunnelUdp
	portTunnelsTcp map[uint32]*PortTunnelTcp
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

func (pfService *PortForwardingService) readPortTunnelRulesFromConfig(c *config.C, protocol string) ([]tunnelConfig, error) {
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
		portTunnelConfig, err := convertToPortTunnelConfig(pfService.l, t)
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

	udp, err := pfService.readPortTunnelRulesFromConfig(c, "udp")
	if err != nil {
		return nil, err
	}

	tcp, err := pfService.readPortTunnelRulesFromConfig(c, "tcp")
	if err != nil {
		return nil, err
	}

	pfService.configPortTunnelsUdp = udp
	pfService.configPortTunnelsTcp = tcp

	return pfService, nil
}

func setupPortTunnelUdp(
	tunService *service.Service,
	localListeningAddress string,
	remoteDestinationAddress string,
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

	localListenConnection, err := net.ListenUDP("udp", localUdpListenAddr)
	if err != nil {
		return nil, err
	}

	l.Infof("UDP port tunnel to '%v': listening on local UDP addr: '%v'",
		remoteUdpAddr, localUdpListenAddr)

	tunnel := &PortTunnelUdp{
		l:                     l,
		tunService:            tunService,
		localUdpListenAddr:    localUdpListenAddr,
		remoteUdpAddr:         remoteUdpAddr,
		localListenConnection: localListenConnection,
	}

	go tunnel.listenLocalPort()

	return tunnel, nil
}

func (pt *PortTunnelUdp) listenLocalPort() error {
	outsideReaderGroup := errgroup.Group{}
	outsidePortReaders := make(map[string]interface{})
	var buf [512 * 1024]byte
	for {
		pt.l.Debug("listening on local UDP port ...")
		n, localSourceAddr, err := pt.localListenConnection.ReadFromUDP(buf[0:])
		if err != nil {
			fmt.Println(err)
			return err
		}

		pt.l.Debugf("handling message from local UDP port: %v", localSourceAddr)

		remoteConnection, err := pt.tunService.DialUDP(pt.remoteUdpAddr.AddrPort().String())
		if err != nil {
			return err
		}

		remoteConnection.Write(buf[:n])

		pt.l.Debugf("send message from %+v, to: %+v, payload-size: %d",
			localSourceAddr, pt.remoteUdpAddr, n)

		_, ok := outsidePortReaders[remoteConnection.LocalAddr().String()]
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

func (pt *PortTunnelUdp) listenLocalOutsidePort() error {
	var buf [512 * 1024]byte
	for {
		pt.l.Debug("listening on local UDP port ...")
		n, localSourceAddr, err := pt.localListenConnection.ReadFromUDP(buf[0:])
		if err != nil {
			fmt.Println(err)
			return err
		}

		pt.l.Debugf("handling message from local UDP port: %v", localSourceAddr)

		remoteConnection, err := pt.tunService.DialUDP(pt.remoteUdpAddr.AddrPort().String())
		if err != nil {
			return err
		}

		remoteConnection.Write(buf[:n])

		pt.l.Debugf("send message from %+v, to: %+v, payload-size: %d",
			localSourceAddr, pt.remoteUdpAddr, n)
	}
}

func setupPortTunnelTcp(
	tunService *service.Service,
	localListeningAddress string,
	remoteDestinationAddress string,
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

	l.Infof("TCP port tunnel to '%v': listening on local TCP addr: '%v'",
		remoteTcpAddr, localTcpListenAddr)

	tunnel := &PortTunnelTcp{
		l:                     l,
		tunService:            tunService,
		localTcpListenAddr:    localTcpListenAddr,
		localListenConnection: localListenPort,
		remoteTcpAddr:         remoteTcpAddr,
	}

	go tunnel.acceptOnLocalListenPort()

	return tunnel, nil
}

func (pt *PortTunnelTcp) acceptOnLocalListenPort() error {
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

func (pt *PortTunnelTcp) handleClientConnection(localConnection *net.TCPConn) error {

	remoteConnection, err := pt.tunService.DialContext(context.Background(), "tcp", pt.remoteTcpAddr.String())
	if err != nil {
		return err
	}

	dataTransferHandler := func(from, to net.Conn) error {
		// no write timeout
		to.SetWriteDeadline(time.Time{})
		from.SetReadDeadline(time.Time{})
		buf := make([]byte, 1)
		for {
			// short read timeout to be able to forward also short packages
			//from.SetReadDeadline(time.Now().Add(time.Millisecond * 3))
			n, err := from.Read(buf)
			if n == 0 && (err != nil) {
				pt.l.Infof("reading from from-connection failed: %v", err)
				return err
			}
			for i := 0; i < n; {
				n, err = to.Write(buf[i:n])
				if err != nil {
					pt.l.Infof("writing to to-connection failed: %v", err)
					return err
				}
				i += n
			}
		}
	}

	errGroup := errgroup.Group{}

	errGroup.Go(func() error { return dataTransferHandler(localConnection, remoteConnection) })
	errGroup.Go(func() error { return dataTransferHandler(remoteConnection, localConnection) })

	return errGroup.Wait()
}

func (t *PortForwardingService) Activate() error {

	t.portTunnelsUdp = make(map[uint32]*PortTunnelUdp)
	for id, config := range t.configPortTunnelsUdp {
		tunnel, err := setupPortTunnelUdp(
			t.tunService,
			config.local,
			config.remote,
			t.l,
		)
		if err != nil {
			t.l.Errorf("failed to setup UDP port tunnel(%d): %+v", id, config)
		}
		t.portTunnelsUdp[uint32(tunnel.localUdpListenAddr.Port)] = tunnel
	}

	t.portTunnelsTcp = make(map[uint32]*PortTunnelTcp)
	for id, config := range t.configPortTunnelsTcp {
		tunnel, err := setupPortTunnelTcp(
			t.tunService,
			config.local,
			config.remote,
			t.l,
		)
		if err != nil {
			t.l.Errorf("failed to setup TCP port tunnel(%d): %+v", id, config)
		}
		t.portTunnelsTcp[uint32(tunnel.localTcpListenAddr.Port)] = tunnel
	}

	return nil
}
