package overlay

import (
	"io"
	"net"

	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/iputil"
	"gvisor.dev/gvisor/pkg/buffer"
)

func NewUserDeviceFromConfig(c *config.C, l *logrus.Logger, tunCidr *net.IPNet, routines int) (Device, error) {
	return NewUserDevice(tunCidr)
}

func NewUserDevice(tunCidr *net.IPNet) (Device, error) {
	// these pipes guarantee each write/read will match 1:1
	return &UserDevice{
		tunCidr:         tunCidr,
		outboundChannel: make(chan *buffer.View, 16),
		inboundChannel:  make(chan *buffer.View, 16),
	}, nil
}

type UserDevice struct {
	tunCidr *net.IPNet

	outboundChannel chan *buffer.View
	inboundChannel  chan *buffer.View
}

func (d *UserDevice) Activate() error {
	return nil
}
func (d *UserDevice) Cidr() *net.IPNet                      { return d.tunCidr }
func (d *UserDevice) Name() string                          { return "faketun0" }
func (d *UserDevice) RouteFor(ip iputil.VpnIp) iputil.VpnIp { return ip }
func (d *UserDevice) NewMultiQueueReader() (io.ReadWriteCloser, error) {
	return d, nil
}

func (d *UserDevice) Pipe() (<-chan *buffer.View, chan<- *buffer.View) {
	return d.inboundChannel, d.outboundChannel
}

func (d *UserDevice) Read(p []byte) (n int, err error) {
	view, ok := <-d.outboundChannel
	if !ok {
		return 0, io.EOF
	}
	return view.Read(p)
}
func (d *UserDevice) WriteTo(w io.Writer) (n int64, err error) {
	view, ok := <-d.outboundChannel
	if !ok {
		return 0, io.EOF
	}
	return view.WriteTo(w)
}

func (d *UserDevice) Write(p []byte) (n int, err error) {
	view := buffer.NewViewWithData(p)
	d.inboundChannel <- view
	return view.Size(), nil
}
func (d *UserDevice) ReadFrom(r io.Reader) (n int64, err error) {
	view := buffer.NewViewSize(2048)
	n, err = view.ReadFrom(r)
	if n > 0 {
		d.inboundChannel <- view
	}
	return
}

func (d *UserDevice) Close() error {
	close(d.inboundChannel)
	close(d.outboundChannel)
	return nil
}
