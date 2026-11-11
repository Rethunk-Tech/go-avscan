package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Totative/go-avscan"
)

func main() {
	// A signal must fail the process (exit 2), not fall through as clean.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("avscan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintf(stderr, "usage: avscan [flags] DIR\n")
		fs.PrintDefaults()
	}
	clamdAddr := fs.String("clamd", "", "clamd address (`unix:/path` or `tcp:host:port`)")
	commandLine := fs.String("command", "", "scanner command line")
	amsi := fs.Bool("amsi", false, "use Windows AMSI")
	timeout := fs.Duration("timeout", 10*time.Minute, "deadline for the whole scan")
	asJSON := fs.Bool("json", false, "print one JSON object")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return 2
	}

	n := 0
	if *clamdAddr != "" {
		n++
	}
	if *commandLine != "" {
		n++
	}
	if *amsi {
		n++
	}
	if n != 1 {
		fs.Usage()
		return 2
	}

	dir := fs.Arg(0)
	fi, err := os.Stat(dir)
	if err != nil || !fi.IsDir() {
		fs.Usage()
		return 2
	}

	var (
		scanner avscan.Scanner
		kind    string
	)
	switch {
	case *clamdAddr != "":
		c, err := parseClamd(*clamdAddr)
		if err != nil {
			fs.Usage()
			return 2
		}
		scanner, kind = c, "clamd"
	case *commandLine != "":
		scanner, kind = avscan.Command{Line: *commandLine}, "command"
	default:
		scanner, kind = avscan.AMSI{AppName: "avscan"}, "amsi"
	}

	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()

	d, found, err := scanner.Scan(ctx, dir)
	clean := err == nil && !found
	code := 0
	switch {
	case err != nil:
		code = 2
	case found:
		code = 1
	}

	if *asJSON {
		if encErr := json.NewEncoder(stdout).Encode(jsonResult{
			Dir:       dir,
			Scanner:   kind,
			Clean:     clean,
			Detection: detectionOrNil(d, found, err),
			Error:     errorOrNil(err),
		}); encErr != nil {
			fmt.Fprintf(stderr, "error: %v\n", encErr)
			return 2
		}
		return code
	}

	switch {
	case err != nil:
		fmt.Fprintf(stderr, "error: %v\n", err)
	case found:
		fmt.Fprintf(stdout, "FOUND: %s in %s (%s)\n", d.Name, d.File, d.Scanner)
	default:
		fmt.Fprintf(stdout, "clean: %s\n", dir)
	}
	return code
}

type jsonResult struct {
	Dir       string            `json:"dir"`
	Scanner   string            `json:"scanner"`
	Clean     bool              `json:"clean"`
	Detection *avscan.Detection `json:"detection"`
	Error     *string           `json:"error"`
}

func detectionOrNil(d avscan.Detection, found bool, err error) *avscan.Detection {
	if err != nil || !found {
		return nil
	}
	return &d
}

func errorOrNil(err error) *string {
	if err == nil {
		return nil
	}
	s := err.Error()
	return &s
}

var errClamdAddr = errors.New("-clamd ADDR must be unix:/path or tcp:host:port")

// parseClamd maps ADDR onto Clamd: Socket is a unix path, and TCP has to go
// through Dial because Socket is never a host:port.
func parseClamd(addr string) (avscan.Clamd, error) {
	network, rest, ok := strings.Cut(addr, ":")
	if !ok || rest == "" {
		return avscan.Clamd{}, errClamdAddr
	}
	switch network {
	case "unix":
		return avscan.Clamd{Socket: rest}, nil
	case "tcp":
		if _, _, err := net.SplitHostPort(rest); err != nil {
			return avscan.Clamd{}, errClamdAddr
		}
		return avscan.Clamd{
			Dial: func(ctx context.Context) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "tcp", rest)
			},
		}, nil
	default:
		return avscan.Clamd{}, errClamdAddr
	}
}
