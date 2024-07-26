package port_forwarder

import (
	"fmt"
	"strconv"

	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/service"
)

func ymlGetStringOfNode(node interface{}) string {
	return fmt.Sprintf("%v", node)
}

func ymlMapGetStringEntry(k string, m map[interface{}]interface{}) string {
	v, ok := m[k]
	if !ok {
		return ""
	}
	return fmt.Sprintf("%v", v)
}

type ymlListNode = []interface{}
type ymlMapNode = map[interface{}]interface{}
type configFactoryFn = func(yml_node ymlMapNode) error
type configFactoryFnMap = map[string]configFactoryFn

type builderData struct {
	l         *logrus.Logger
	target    ConfigList
	factories map[string]configFactoryFnMap
}

func ConstructFromConfig(
	tunService *service.Service,
	l *logrus.Logger,
	c *config.C,
) (*PortForwardingService, error) {

	pfService := &PortForwardingService{
		l:                     l,
		tunService:            tunService,
		configPortForwardings: make(map[string]ForwardConfig),
		portForwardings:       make(map[string]interface{}),
	}

	builder := builderData{
		l:         l,
		target:    pfService,
		factories: map[string]configFactoryFnMap{},
	}

	in := configFactoryFnMap{}
	in["udp"] = func(yml_node ymlMapNode) error {
		return builder.convertToForwardConfigIncoming(l, yml_node, false)
	}
	in["tcp"] = func(yml_node ymlMapNode) error {
		return builder.convertToForwardConfigIncoming(l, yml_node, true)
	}
	builder.factories["inbound"] = in

	out := configFactoryFnMap{}
	out["udp"] = func(yml_node ymlMapNode) error {
		return builder.convertToForwardConfigOutgoing(l, yml_node, false)
	}
	out["tcp"] = func(yml_node ymlMapNode) error {
		return builder.convertToForwardConfigOutgoing(l, yml_node, true)
	}
	builder.factories["outbound"] = out

	for _, direction := range [...]string{"inbound", "outbound"} {
		cfg_fwds := c.Get("port_forwarding." + direction)
		if cfg_fwds == nil {
			continue
		}

		cfg_fwds_list, ok := cfg_fwds.(ymlListNode)
		if !ok {
			return nil, fmt.Errorf("yml node \"port_forwarding.%s\" needs to be a list", direction)
		}

		for fwd_idx, node := range cfg_fwds_list {
			node_map, ok := node.(ymlMapNode)
			if !ok {
				return nil, fmt.Errorf("child yml node of \"port_forwarding.%s\" needs to be a map", direction)
			}

			protocols, ok := node_map["protocols"]
			if !ok {
				return nil, fmt.Errorf("child yml node of \"port_forwarding.%s\" needs to have a child \"protocols\"", direction)
			}

			protocols_list, ok := protocols.(ymlListNode)
			if !ok {
				return nil, fmt.Errorf("child yml node of \"port_forwarding.%s\" needs to have a child \"protocols\" that is a yml list", direction)
			}

			for _, proto := range protocols_list {
				proto_str := ymlGetStringOfNode(proto)
				factoryFn, ok := builder.factories[direction][proto_str]
				if !ok {
					return nil, fmt.Errorf("child yml node of \"port_forwarding.%s.%d.protocols\" doesn't support: %s", direction, fwd_idx, proto_str)
				}

				factoryFn(node_map)
			}
		}
	}

	return pfService, nil
}

func (builder *builderData) convertToForwardConfigOutgoing(
	_ *logrus.Logger,
	m ymlMapNode,
	isTcp bool,
) error {
	fwd_port := ForwardConfigOutgoing{
		localListen:   ymlMapGetStringEntry("local_address", m),
		remoteConnect: ymlMapGetStringEntry("remote_address", m),
	}

	var cfg ForwardConfig
	if isTcp {
		cfg = ForwardConfigOutgoingTcp{fwd_port}
	} else {
		cfg = ForwardConfigOutgoingUdp{fwd_port}
	}

	builder.target.AddConfig(cfg)

	return nil
}

func (builder *builderData) convertToForwardConfigIncoming(
	_ *logrus.Logger,
	m ymlMapNode,
	isTcp bool,
) error {

	v, err := strconv.ParseUint(ymlMapGetStringEntry("port", m), 10, 32)
	if err != nil {
		return err
	}

	fwd_port := ForwardConfigIncoming{
		port:                uint32(v),
		forwardLocalAddress: ymlMapGetStringEntry("forward_address", m),
	}

	var cfg ForwardConfig
	if isTcp {
		cfg = ForwardConfigIncomingTcp{fwd_port}
	} else {
		cfg = ForwardConfigIncomingUdp{fwd_port}
	}

	builder.target.AddConfig(cfg)

	return nil
}
