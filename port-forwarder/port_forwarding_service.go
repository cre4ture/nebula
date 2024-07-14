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

	//portTunnelsUdp map[uint32]*PortTunnelUdp
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

func ConstructFromConfig(l *logrus.Logger, c *config.C) (*PortForwardingService, error) {

	pfService := &PortForwardingService{
		l: l,
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
				pt.l.Infof("reading from local client connection failed: %v", err)
				return err
			}
			for i := 0; i < n; {
				n, err = to.Write(buf[i:n])
				if err != nil {
					pt.l.Infof("writing to remote server connection failed: %v", err)
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

func (t *PortForwardingService) Activate(tunService *service.Service) error {

	//for id, config := range t.configPortTunnelsUdp {
	//	tunnel, err := setupPortTunnelUdp(
	//		config.local,
	//		config.remote,
	//		t.cidr.IP,
	//		func(out []byte) {
	//			t.read <- out
	//		},
	//		t.l,
	//	)
	//	if err != nil {
	//		t.l.Errorf("failed to setup UDP port tunnel(%d): %+v", id, config)
	//	}
	//	t.portTunnelsUdp[uint32(tunnel.localUdpListenAddr.Port)] = tunnel
	//	go tunnel.listenLocalPort()
	//}

	t.tunService = tunService

	t.portTunnelsTcp = make(map[uint32]*PortTunnelTcp)
	for id, config := range t.configPortTunnelsTcp {
		tunnel, err := setupPortTunnelTcp(
			tunService,
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
