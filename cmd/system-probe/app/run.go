package app

import (
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	_ "net/http/pprof" // Blank import used because this isn't directly used in this file

	"github.com/DataDog/datadog-agent/cmd/agent/common/signals"
	"github.com/DataDog/datadog-agent/cmd/system-probe/api"
	"github.com/DataDog/datadog-agent/cmd/system-probe/config"
	"github.com/DataDog/datadog-agent/cmd/system-probe/modules"
	"github.com/DataDog/datadog-agent/cmd/system-probe/utils"
	ddconfig "github.com/DataDog/datadog-agent/pkg/config"
	"github.com/DataDog/datadog-agent/pkg/pidfile"
	"github.com/DataDog/datadog-agent/pkg/process/net"
	"github.com/DataDog/datadog-agent/pkg/process/statsd"
	ddruntime "github.com/DataDog/datadog-agent/pkg/runtime"
	"github.com/DataDog/datadog-agent/pkg/util"
	"github.com/DataDog/datadog-agent/pkg/util/log"
	"github.com/DataDog/datadog-agent/pkg/util/profiling"
	"github.com/DataDog/datadog-agent/pkg/version"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"gopkg.in/DataDog/dd-trace-go.v1/profiler"
)

var (
	// flags variables
	pidfilePath string

	runCmd = &cobra.Command{
		Use:   "run",
		Short: "Run the System Probe",
		Long:  `Runs the system-probe in the foreground`,
		RunE:  run,
	}
)

func init() {
	// attach the command to the root
	SysprobeCmd.AddCommand(runCmd)

	// local flags
	runCmd.Flags().StringVarP(&pidfilePath, "pid", "p", "", "path to the pidfile")
}

// Start the main loop
func run(_ *cobra.Command, _ []string) error {
	defer func() {
		StopSystemProbe()
	}()

	// prepare go runtime
	ddruntime.SetMaxProcs()

	// Make a channel to exit the function
	stopCh := make(chan error)

	// Setup a channel to catch OS signals
	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, os.Interrupt, syscall.SIGTERM)

	go func() {
		// Set up the signals async so we can Start the agent
		select {
		case <-signals.Stopper:
			log.Info("Received stop command, shutting down...")
			stopCh <- nil
		case <-signals.ErrorStopper:
			_ = log.Critical("system-probe has encountered an error, shutting down...")
			stopCh <- fmt.Errorf("shutting down because of an error")
		case sig := <-signalCh:
			log.Infof("Received signal '%s', shutting down...", sig)
			stopCh <- nil
		}
	}()

	// By default systemd redirects the stdout to journald. When journald is stopped or crashes we receive a SIGPIPE signal.
	// Go ignores SIGPIPE signals unless it is when stdout or stdout is closed, in this case the agent is stopped.
	// We never want the agent to stop upon receiving SIGPIPE, so we intercept the SIGPIPE signals and just discard them.
	sigpipeCh := make(chan os.Signal, 1)
	signal.Notify(sigpipeCh, syscall.SIGPIPE)
	go func() {
		for range sigpipeCh {
			// do nothing
		}
	}()

	if err := StartSystemProbe(); err != nil {
		return err
	}
	log.Infof("system probe successfully started")

	select {
	case err := <-stopCh:
		return err
	}
}

// StartSystemProbe Initializes the system-probe process
func StartSystemProbe() error {
	cfg, err := config.New(configPath)
	if err != nil {
		return log.Criticalf("Failed to create agent config: %s", err)
	}

	err = ddconfig.SetupLogger(
		loggerName,
		cfg.LogLevel,
		cfg.LogFile,
		ddconfig.GetSyslogURI(),
		ddconfig.Datadog.GetBool("syslog_rfc"),
		ddconfig.Datadog.GetBool("log_to_console"),
		ddconfig.Datadog.GetBool("log_format_json"),
	)
	if err != nil {
		return log.Criticalf("failed to setup configured logger: %s", err)
	}

	color.NoColor = true
	log.Infof("running system-probe with version: %s", versionString())
	color.NoColor = false

	if err := util.SetupCoreDump(); err != nil {
		log.Warnf("Can't setup core dumps: %v, core dumps might not be available after a crash", err)
	}

	if pidfilePath != "" {
		if err := pidfile.WritePID(pidfilePath); err != nil {
			return log.Errorf("Error while writing PID file, exiting: %v", err)
		}
		log.Infof("pid '%d' written to pid file '%s'", os.Getpid(), pidfilePath)
	}

	// Exit if system probe is disabled
	if cfg.ExternalSystemProbe || !cfg.Enabled {
		log.Info("system probe not enabled. exiting.")
		return nil
	}

	if cfg.ProfilingEnabled {
		if err := enableProfiling(cfg); err != nil {
			log.Warnf("failed to enable profiling: %s", err)
		}
		defer profiling.Stop()
	}

	if err := statsd.Configure(cfg.StatsdHost, cfg.StatsdPort); err != nil {
		return log.Criticalf("Error configuring statsd: %s", err)
	}

	conn, err := net.NewListener(cfg.SocketAddress)
	if err != nil {
		return log.Criticalf("Error creating IPC socket: %s", err)
	}

	// if a debug port is specified, we expose the default handler to that port
	if cfg.DebugPort > 0 {
		go func() {
			err := http.ListenAndServe(fmt.Sprintf("localhost:%d", cfg.DebugPort), http.DefaultServeMux)
			if err != nil && err != http.ErrServerClosed {
				log.Errorf("Error creating debug HTTP server: %v", err)
			}
		}()
	}

	httpMux := http.NewServeMux()
	err = api.Register(cfg, httpMux, modules.All)
	if err != nil {
		return log.Criticalf("failed to create system probe: %s", err)
	}

	// Register stats endpoint
	httpMux.HandleFunc("/debug/stats", func(w http.ResponseWriter, req *http.Request) {
		stats := api.GetStats()
		utils.WriteAsJSON(w, stats)
	})

	go func() {
		err = http.Serve(conn.GetListener(), httpMux)
		if err != nil && err != http.ErrServerClosed {
			log.Errorf("Error creating HTTP server: %s", err)
		}
	}()

	return nil
}

// StopSystemProbe Tears down the system-probe process
func StopSystemProbe() {
	api.Close()
	profiler.Stop()
	_ = os.Remove(pidfilePath)
	log.Flush()
}

func enableProfiling(cfg *config.Config) error {
	var site string
	v, _ := version.Agent()

	// check if TRACE_AGENT_URL is set, in which case, forward the profiles to the trace agent
	if traceAgentURL := os.Getenv("TRACE_AGENT_URL"); len(traceAgentURL) > 0 {
		site = fmt.Sprintf(profiling.ProfilingLocalURLTemplate, traceAgentURL)
	} else {
		site = fmt.Sprintf(profiling.ProfileURLTemplate, cfg.ProfilingSite)
		if cfg.ProfilingURL != "" {
			site = cfg.ProfilingURL
		}
	}

	return profiling.Start(
		cfg.ProfilingAPIKey,
		site,
		cfg.ProfilingEnvironment,
		"system-probe",
		fmt.Sprintf("version:%v", v),
	)
}
