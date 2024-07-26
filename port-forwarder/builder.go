package port_forwarder

import (
	"errors"
	"fmt"
	"strconv"

	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/service"
)

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
	pfService.configPortForwardingsUdpOutgoing, err = pfService.readOutgoingForwardingRulesFromConfig(c, "udp")
	if err != nil {
		return nil, err
	}

	pfService.configPortForwardingsTcpOutgoing, err = pfService.readOutgoingForwardingRulesFromConfig(c, "tcp")
	if err != nil {
		return nil, err
	}

	pfService.configPortForwardingsUdpIncoming, err = pfService.readIncomingForwardingRulesFromConfig(c, "udp")
	if err != nil {
		return nil, err
	}

	pfService.configPortForwardingsTcpIncoming, err = pfService.readIncomingForwardingRulesFromConfig(c, "tcp")
	if err != nil {
		return nil, err
	}

	return pfService, nil
}

func (pfService *PortForwardingService) readOutgoingForwardingRulesFromConfig(
	c *config.C, protocol string,
) ([]forwardConfigOutgoing, error) {
	table := "port_forwarding.outgoing." + protocol
	out := make([]forwardConfigOutgoing, 0)

	r := c.Get(table)
	if r == nil {
		return nil, nil
	}

	rs, ok := r.([]interface{})
	if !ok {
		return nil, fmt.Errorf("%s failed to parse, should be an array of port forwardings", table)
	}

	for i, t := range rs {
		portForwardingConfig, err := convertToForwardConfigOutgoing(pfService.l, t)
		if err != nil {
			return nil, fmt.Errorf("%s port forwarding #%v; %s", table, i, err)
		}
		out = append(out, portForwardingConfig)
	}

	return out, nil
}

func (pfService *PortForwardingService) readIncomingForwardingRulesFromConfig(
	c *config.C, protocol string,
) ([]forwardConfigIncoming, error) {
	table := "port_forwarding.incoming." + protocol
	out := make([]forwardConfigIncoming, 0)

	r := c.Get(table)
	if r == nil {
		return nil, nil
	}

	rs, ok := r.([]interface{})
	if !ok {
		return nil, fmt.Errorf("%s failed to parse, should be an array of port forwardings", table)
	}

	for i, t := range rs {
		portForwardingConfig, err := convertToForwardConfigIncoming(pfService.l, t)
		if err != nil {
			return nil, fmt.Errorf("%s port forwarding #%v; %s", table, i, err)
		}
		out = append(out, portForwardingConfig)
	}

	return out, nil
}

func convertToForwardConfigOutgoing(_ *logrus.Logger, p interface{}) (forwardConfigOutgoing, error) {
	fwd_port := forwardConfigOutgoing{}

	m, ok := p.(map[interface{}]interface{})
	if !ok {
		return fwd_port, errors.New("could not parse port forwarding config")
	}

	toString := func(k string, m map[interface{}]interface{}) string {
		v, ok := m[k]
		if !ok {
			return ""
		}
		return fmt.Sprintf("%v", v)
	}

	fwd_port.localListen = toString("local_address", m)
	fwd_port.remoteConnect = toString("remote_address", m)

	return fwd_port, nil
}

func convertToForwardConfigIncoming(_ *logrus.Logger, p interface{}) (forwardConfigIncoming, error) {
	fwd_port := forwardConfigIncoming{}

	m, ok := p.(map[interface{}]interface{})
	if !ok {
		return fwd_port, errors.New("could not parse port forwarding config")
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
		return fwd_port, err
	}
	fwd_port.port = uint32(v)
	fwd_port.forwardLocalAddress = toString("forward_address", m)

	return fwd_port, nil
}
