package main

import (
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	rdns "github.com/folbricht/routedns"
	"github.com/folbricht/routedns/api"
	"github.com/spf13/cobra"
)

type options struct {
	logLevel uint32
	version  bool
}

func main() {
	var opt options
	cmd := &cobra.Command{
		Use:   "routedns <config> [<config>..]",
		Short: "DNS stub resolver, proxy and router",
		Long: `DNS stub resolver, proxy and router.

Listens for incoming DNS requests, routes, modifies and
forwards to upstream resolvers. Supports plain DNS over
UDP and TCP as well as DNS-over-TLS and DNS-over-HTTPS
as listener and client protocols.

Routes can be defined to send requests for certain queries;
by record type, query name or client-IP to different modifiers
or upstream resolvers.

Configuration can be split over multiple files with listeners,
groups and routers defined in different files and provided as
arguments.
`,
		Example: `  routedns config.toml`,
		Args:    cobra.MinimumNArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			return start(opt, args)
		},
		SilenceUsage: true,
	}

	cmd.Flags().Uint32VarP(&opt.logLevel, "log-level", "l", 4, "log level; 0=None .. 6=Trace")
	cmd.Flags().BoolVarP(&opt.version, "version", "v", false, "Prints code version string")

	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}

}

// Functions to call on shutdown
var onClose []func()

func start(opt options, args []string) error {
	// Set the log level in the library package
	if opt.logLevel > 6 {
		return fmt.Errorf("invalid log level: %d", opt.logLevel)
	}
	if opt.version {
		printVersion()
		os.Exit(0)
	} else {
		if len(args) < 1 {
			return errors.New("not enough arguments")
		}

	}

	config, err := api.LoadConfig(args...)
	if err != nil {
		return err
	}

	manager, err := config.GetPanelManager(opt.logLevel)
	if err != nil {
		return err
	}

	// Start the listeners
	for _, l := range manager.Listeners {
		go func(l rdns.Listener) {
			for {
				err := l.Start()
				rdns.Log.WithError(err).Error("listener failed")
				time.Sleep(time.Second)
			}
		}(l)
	}

	// Graceful shutdown
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	<-sig
	rdns.Log.Info("stopping")
	for _, f := range onClose {
		f()
	}

	return nil
}

func printVersion() {
	fmt.Println("Build: ", rdns.BuildNumber)
	fmt.Println("Build Time: ", rdns.BuildTime)
	fmt.Println("Version: ", rdns.BuildVersion)
}
