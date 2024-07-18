package overlay

import (
	"io"
	"net"
	"sync/atomic"

	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/cidr"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/iputil"
)

func NewUserDeviceFromConfig(c *config.C, l *logrus.Logger, tunCidr *net.IPNet, routines int) (Device, error) {
	d, err := NewUserDevice(tunCidr)
	if err != nil {
		return nil, err
	}

	_, routes, err := getAllRoutesFromConfig(c, tunCidr, true)
	if err != nil {
		return nil, err
	}

	routeTree, err := makeRouteTree(l, routes, true)
	if err != nil {
		return nil, err
	}

	newDefaultMTU := c.GetInt("tun.mtu", DefaultMTU)
	for i, r := range routes {
		if r.MTU == 0 {
			routes[i].MTU = newDefaultMTU
		}
	}

	d.routeTree.Store(routeTree)

	return d, nil
}

func NewUserDevice(tunCidr *net.IPNet) (*UserDevice, error) {
	// these pipes guarantee each write/read will match 1:1
	or, ow := io.Pipe()
	ir, iw := io.Pipe()
	return &UserDevice{
		tunCidr:        tunCidr,
		outboundReader: or,
		outboundWriter: ow,
		inboundReader:  ir,
		inboundWriter:  iw,
	}, nil
}

type UserDevice struct {
	tunCidr *net.IPNet

	outboundReader *io.PipeReader
	outboundWriter *io.PipeWriter

	inboundReader *io.PipeReader
	inboundWriter *io.PipeWriter

	routeTree atomic.Pointer[cidr.Tree4[iputil.VpnIp]]
}

func (d *UserDevice) Activate() error {
	return nil
}
func (d *UserDevice) Cidr() *net.IPNet { return d.tunCidr }
func (d *UserDevice) Name() string     { return "faketun0" }
func (d *UserDevice) RouteFor(ip iputil.VpnIp) iputil.VpnIp {
	_, r := d.routeTree.Load().MostSpecificContains(ip)
	return r
}
func (d *UserDevice) NewMultiQueueReader() (io.ReadWriteCloser, error) {
	return d, nil
}

func (d *UserDevice) Pipe() (*io.PipeReader, *io.PipeWriter) {
	return d.inboundReader, d.outboundWriter
}

func (d *UserDevice) Read(p []byte) (n int, err error) {
	return d.outboundReader.Read(p)
}
func (d *UserDevice) Write(p []byte) (n int, err error) {
	return d.inboundWriter.Write(p)
}
func (d *UserDevice) Close() error {
	d.inboundWriter.Close()
	d.outboundWriter.Close()
	return nil
}
