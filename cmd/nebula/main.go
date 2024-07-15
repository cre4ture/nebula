package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula"
	"github.com/slackhq/nebula/config"
	port_forwarder "github.com/slackhq/nebula/port-forwarder"
	"github.com/slackhq/nebula/service"
	"github.com/slackhq/nebula/util"
)

// A version string that can be set with
//
//	-ldflags "-X main.Build=SOMEVERSION"
//
// at compile-time.
var Build string

func main() {
	configPath := flag.String("config", "", "Path to either a file or directory to load configuration from")
	configTest := flag.Bool("test", false, "Test the config and print the end result. Non zero exit indicates a faulty config")
	printVersion := flag.Bool("version", false, "Print version")
	printUsage := flag.Bool("help", false, "Print command line usage")
	logLevel := flag.String("log-level", "", "log level to activate")

	flag.Parse()

	if *printVersion {
		fmt.Printf("Version: %s\n", Build)
		os.Exit(0)
	}

	if *printUsage {
		flag.Usage()
		os.Exit(0)
	}

	if *configPath == "" {
		fmt.Println("-config flag must be set")
		flag.Usage()
		os.Exit(1)
	}

	l := logrus.New()
	l.Out = os.Stdout
	level, err := logrus.ParseLevel(*logLevel)
	if err != nil {
		fmt.Printf("failed to get log level from argument: %s", err)
		os.Exit(1)
	}
	l.SetLevel(level)

	c := config.NewC(l)
	err = c.Load(*configPath)
	if err != nil {
		fmt.Printf("failed to load config: %s", err)
		os.Exit(1)
	}

	userspace_tun := c.GetBool("tun.user", false)
	if userspace_tun {
		if *configTest {
			util.LogWithContextIfNeeded("Failed to start",
				errors.New("config test currently not supported for user-tun"), l)
			os.Exit(1)
		}

		service, err := service.New(c)
		if err != nil {
			util.LogWithContextIfNeeded("Failed to start", err, l)
			os.Exit(1)
		}

		// initialize port forwarding:
		pf_service, err := port_forwarder.ConstructFromConfig(service, l, c)
		if err != nil {
			util.LogWithContextIfNeeded("Failed to start", err, l)
			os.Exit(1)
		}
		pf_service.Activate()

		// wait for termination request
		signalChannel := make(chan os.Signal, 1)
		signal.Notify(signalChannel, syscall.SIGINT, syscall.SIGTERM)
		fmt.Println("Running, press ctrl+c to shutdown...")
		<-signalChannel

		// shutdown:
		service.Close()
		if err := service.Wait(); err != nil {
			util.LogWithContextIfNeeded("Failed to stop", err, l)
		}

	} else {

		ctrl, err := nebula.Main(c, *configTest, Build, l, nil)
		if err != nil {
			util.LogWithContextIfNeeded("Failed to start", err, l)
			os.Exit(1)
		}

		if !*configTest {
			ctrl.Start()
			notifyReady(l)
			ctrl.ShutdownBlock()
		}
	}

	os.Exit(0)
}
