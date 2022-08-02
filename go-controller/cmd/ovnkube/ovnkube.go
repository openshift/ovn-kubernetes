package main

import (
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"text/tabwriter"
	"text/template"
	"time"

	"k8s.io/client-go/tools/record"
	"k8s.io/klog/v2"

	libovsdbclient "github.com/ovn-org/libovsdb/client"
	"github.com/urfave/cli/v2"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/factory"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/libovsdb"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/metrics"
	ovnnode "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/node"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/ovn"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"

	kexec "k8s.io/utils/exec"
)

const (
	// CustomAppHelpTemplate helps in grouping options to ovnkube
	CustomAppHelpTemplate = `NAME:
   {{.Name}} - {{.Usage}}

USAGE:
   {{.HelpName}} [global options]

VERSION:
   {{.Version}}{{if .Description}}

DESCRIPTION:
   {{.Description}}{{end}}

COMMANDS:{{range .VisibleCategories}}{{if .Name}}

   {{.Name}}:{{end}}{{range .VisibleCommands}}
     {{join .Names ", "}}{{"\t"}}{{.Usage}}{{end}}{{end}}

GLOBAL OPTIONS:{{range $title, $category := getFlagsByCategory}}
   {{upper $title}}
   {{range $index, $option := $category}}{{if $index}}
   {{end}}{{$option}}{{end}}
   {{end}}`
)

func getFlagsByCategory() map[string][]cli.Flag {
	m := map[string][]cli.Flag{}
	m["Generic Options"] = config.CommonFlags
	m["CNI Options"] = config.CNIFlags
	m["K8s-related Options"] = config.K8sFlags
	m["OVN Northbound DB Options"] = config.OvnNBFlags
	m["OVN Southbound DB Options"] = config.OvnSBFlags
	m["OVN Gateway Options"] = config.OVNGatewayFlags
	m["Master HA Options"] = config.MasterHAFlags
	m["OVN Kube Node Options"] = config.OvnKubeNodeFlags
	m["Monitoring Options"] = config.MonitoringFlags
	m["IPFIX Flow Tracing Options"] = config.IPFIXFlags

	return m
}

// borrowed from cli packages' printHelpCustom()
func printOvnKubeHelp(out io.Writer, templ string, data interface{}, customFunc map[string]interface{}) {
	funcMap := template.FuncMap{
		"join":               strings.Join,
		"upper":              strings.ToUpper,
		"getFlagsByCategory": getFlagsByCategory,
	}
	for key, value := range customFunc {
		funcMap[key] = value
	}

	w := tabwriter.NewWriter(out, 1, 8, 2, ' ', 0)
	t := template.Must(template.New("help").Funcs(funcMap).Parse(templ))
	err := t.Execute(w, data)
	if err == nil {
		_ = w.Flush()
	}
}

func main() {
	cli.HelpPrinterCustom = printOvnKubeHelp
	c := cli.NewApp()
	c.Name = "ovnkube"
	c.Usage = "run ovnkube to start master, node, and gateway services"
	c.Version = config.Version
	c.CustomAppHelpTemplate = CustomAppHelpTemplate
	c.Flags = config.GetFlags(nil)

	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)
	c.Action = func(ctx *cli.Context) error {
		return runOvnKube(ctx, cancel)
	}

	// trap SIGHUP, SIGINT, SIGTERM, SIGQUIT and
	// cancel the context
	exitCh := make(chan os.Signal, 1)
	signal.Notify(exitCh,
		syscall.SIGHUP,
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGQUIT)
	defer func() {
		signal.Stop(exitCh)
		cancel()
	}()
	go func() {
		select {
		case s := <-exitCh:
			klog.Infof("Received signal %s. Shutting down", s)
			cancel()
		case <-ctx.Done():
		}
	}()

	if err := c.RunContext(ctx, os.Args); err != nil {
		klog.Exit(err)
	}
}

func delPidfile(pidfile string) {
	if pidfile != "" {
		if _, err := os.Stat(pidfile); err == nil {
			if err := os.Remove(pidfile); err != nil {
				klog.Errorf("%s delete failed: %v", pidfile, err)
			}
		}
	}
}

func setupPIDFile(pidfile string) error {
	// need to test if already there
	_, err := os.Stat(pidfile)

	// Create if it doesn't exist, else exit with error
	if os.IsNotExist(err) {
		if err := ioutil.WriteFile(pidfile, []byte(fmt.Sprintf("%d", os.Getpid())), 0o644); err != nil {
			klog.Errorf("Failed to write pidfile %s (%v). Ignoring..", pidfile, err)
		}
	} else {
		// get the pid and see if it exists
		pid, err := ioutil.ReadFile(pidfile)
		if err != nil {
			return fmt.Errorf("pidfile %s exists but can't be read: %v", pidfile, err)
		}
		_, err1 := os.Stat("/proc/" + string(pid[:]) + "/cmdline")
		if os.IsNotExist(err1) {
			// Left over pid from dead process
			if err := ioutil.WriteFile(pidfile, []byte(fmt.Sprintf("%d", os.Getpid())), 0o644); err != nil {
				klog.Errorf("Failed to write pidfile %s (%v). Ignoring..", pidfile, err)
			}
		} else {
			return fmt.Errorf("pidfile %s exists and ovnkube is running", pidfile)
		}
	}

	return nil
}

func runOvnKube(ctx *cli.Context, cancel context.CancelFunc) error {
	pidfile := ctx.String("pidfile")
	if pidfile != "" {
		defer delPidfile(pidfile)
		if err := setupPIDFile(pidfile); err != nil {
			return err
		}
	}

	exec := kexec.New()
	_, err := config.InitConfig(ctx, exec, nil)
	if err != nil {
		return err
	}

	if err = util.SetExec(exec); err != nil {
		return fmt.Errorf("failed to initialize exec helper: %v", err)
	}

	ovnClientset, err := util.NewOVNClientset(&config.Kubernetes)
	if err != nil {
		return err
	}

	master := ctx.String("init-master")
	node := ctx.String("init-node")

	cleanupNode := ctx.String("cleanup-node")
	if cleanupNode != "" {
		if master != "" || node != "" {
			return fmt.Errorf("cannot specify cleanup-node together with 'init-node or 'init-master'")
		}

		if err = ovnnode.CleanupClusterNode(cleanupNode); err != nil {
			return err
		}
		return nil
	}

	if master == "" && node == "" {
		return fmt.Errorf("need to run ovnkube in either master and/or node mode")
	}

	stopChan := make(chan struct{})
	wg := &sync.WaitGroup{}
	var watchFactory factory.Shutdownable
	var masterWatchFactory *factory.WatchFactory
	var masterEventRecorder record.EventRecorder
	if master != "" {
		var err error
		// create factory and start the controllers asked for
		masterWatchFactory, err = factory.NewMasterWatchFactory(ovnClientset)
		if err != nil {
			return err
		}
		watchFactory = masterWatchFactory
		var libovsdbOvnNBClient, libovsdbOvnSBClient libovsdbclient.Client

		if libovsdbOvnNBClient, err = libovsdb.NewNBClient(stopChan); err != nil {
			return fmt.Errorf("error when trying to initialize libovsdb NB client: %v", err)
		}

		if libovsdbOvnSBClient, err = libovsdb.NewSBClient(stopChan); err != nil {
			return fmt.Errorf("error when trying to initialize libovsdb SB client: %v", err)
		}

		// register prometheus metrics that do not depend on becoming ovnkube-master leader
		metrics.RegisterMasterBase()

		masterEventRecorder = util.EventRecorder(ovnClientset.KubeClient)
		ovnController := ovn.NewOvnController(ovnClientset, masterWatchFactory, stopChan, nil,
			libovsdbOvnNBClient, libovsdbOvnSBClient, masterEventRecorder)
		if err := ovnController.Start(master, wg, ctx.Context, cancel); err != nil {
			return err
		}
	}

	if node != "" {
		var nodeWatchFactory factory.NodeWatchFactory
		var nodeEventRecorder record.EventRecorder

		if masterWatchFactory == nil {
			var err error
			nodeWatchFactory, err = factory.NewNodeWatchFactory(ovnClientset, node)
			if err != nil {
				return err
			}
			watchFactory = nodeWatchFactory
		} else {
			nodeWatchFactory = masterWatchFactory
		}

		if masterEventRecorder == nil {
			nodeEventRecorder = util.EventRecorder(ovnClientset.KubeClient)
		} else {
			nodeEventRecorder = masterEventRecorder
		}

		if config.Kubernetes.Token == "" {
			return fmt.Errorf("cannot initialize node without service account 'token'. Please provide one with --k8s-token argument")
		}
		// register ovnkube node specific prometheus metrics exported by the node
		metrics.RegisterNodeMetrics()
		start := time.Now()
		n := ovnnode.NewNode(ovnClientset.KubeClient, nodeWatchFactory, node, stopChan, nodeEventRecorder)
		if err := n.Start(ctx.Context, wg); err != nil {
			return err
		}
		end := time.Since(start)
		metrics.MetricNodeReadyDuration.Set(end.Seconds())
	}

	// now that ovnkube master/node are running, lets expose the metrics HTTP endpoint if configured
	// start the prometheus server to serve OVN K8s Metrics (default master port: 9409, node port: 9410)
	if config.Metrics.BindAddress != "" {
		metrics.StartMetricsServer(config.Metrics.BindAddress, config.Metrics.EnablePprof,
			config.Metrics.NodeServerCert, config.Metrics.NodeServerPrivKey, stopChan, wg)
	}

	// start the prometheus server to serve OVS and OVN Metrics (default port: 9476)
	// Note: for ovnkube node mode dpu-host no metrics is required as ovs/ovn is not running on the node.
	if config.OvnKubeNode.Mode != types.NodeModeDPUHost && config.Metrics.OVNMetricsBindAddress != "" {
		if config.Metrics.ExportOVSMetrics {
			metrics.RegisterOvsMetricsWithOvnMetrics(stopChan)
		}
		metrics.RegisterOvnMetrics(ovnClientset.KubeClient, node, stopChan)
		metrics.StartOVNMetricsServer(config.Metrics.OVNMetricsBindAddress,
			config.Metrics.NodeServerCert, config.Metrics.NodeServerPrivKey, stopChan, wg)
	}

	// run until cancelled
	<-ctx.Context.Done()
	close(stopChan)
	watchFactory.Shutdown()
	wg.Wait()
	return nil
}
