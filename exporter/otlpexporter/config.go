// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otlpexporter // import "go.opentelemetry.io/collector/exporter/otlpexporter"

import (
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/config/configgrpc"
	"go.opentelemetry.io/collector/config/configretry"
	"go.opentelemetry.io/collector/exporter/exporterhelper"
)

// Config defines configuration for OTLP exporter.
type Config struct {
	exporterhelper.TimeoutSettings `mapstructure:",squash"`     // squash ensures fields are correctly decoded in embedded struct.
	QueueConfig                    exporterhelper.QueueSettings `mapstructure:"sending_queue"`
	RetryConfig                    configretry.BackOffConfig    `mapstructure:"retry_on_failure"`

	configgrpc.ClientConfig `mapstructure:",squash"` // squash ensures fields are correctly decoded in embedded struct.
}

func (c *Config) Validate() error {
	hostport := c.Endpoint
	sanitizedEndpoint, scheme := c.sanitizedEndpoint()
	if sanitizedEndpoint == "" {
		return errors.New(`requires a non-empty "endpoint"`)
	}
	if scheme == "dns" {
		validDnsRegex := regexp.MustCompile("^dns://.*/(.+)")
		if !validDnsRegex.Match([]byte(c.Endpoint)) {
			return fmt.Errorf("invalid dns scheme format")
		}
		matches := validDnsRegex.FindStringSubmatch(c.Endpoint)
		if len(matches) > 1 && matches[1] != "" {
			hostport = matches[1]
		}
	}

	hostport = sanitizedEndpoint
	// validate host and post exist next to each other. example <host>:<port>/foo/bar
	idx := strings.Index(sanitizedEndpoint, "/")
	if idx > -1 && (scheme == "http" || scheme == "https") {
		hostport = sanitizedEndpoint[:idx]
	}
	// Validate that the port is in the address
	_, port, err := net.SplitHostPort(hostport)
	if err != nil {
		return err
	}
	if _, err := strconv.Atoi(port); err != nil {
		return fmt.Errorf(`invalid port "%s"`, port)
	}

	return nil
}

// sanitizedEndpoint returns two params
//
// 1. sanaitized endpoint: An endpoint with the scheme part removed (Only if scheme is http or https or dns).
// Example: For the string "<scheme>://<host>:<port>", it returns "<host>:<port>"
//
// 2. Scheme: Scheme of the endpoint. Example: For the string "<scheme>://<host>:<port>", it returns <scheme>.
// It returns empty scheme if the scheme is not present in the endpoint.
//
// Example:
//
//   - "dns://authority/backend.example.com:4317"       --> "dns"
//   - "dns://backend.example.com:4317"                 --> "dns"
//   - "dns:///backend.example.com:8080"                --> "dns"
//   - "dns://my-backend:4317"                          --> "dns"
//   - "http://backend.example.com:4317"                --> "http"
//   - "https://backend.example.com:4317"               --> "https"
//   - "uds:///run/containerd/containerd.sock"          --> "uds"
//   - "xds:///wallet.grpcwallet.io"                    --> "xds"
//   - "ipv4:198.51.100.123:50051"                      --> ""
func (c *Config) sanitizedEndpoint() (string, string) {
	scheme := ""
	sanitizedEndpoint := c.Endpoint
	sanatizeSchemeRegexp := regexp.MustCompile(`(^[a-z]*):[\/]*`)
	matches := sanatizeSchemeRegexp.FindStringSubmatch(c.Endpoint)
	if len(matches) > 1 {
		scheme = matches[1]
	}
	// Preserving existing behavouir. Trim only in case of "http", "https" and "dns". Ref:
	if scheme == "http" || scheme == "https" || scheme == "dns" {
		sanitizedEndpoint = sanatizeSchemeRegexp.ReplaceAllString(sanitizedEndpoint, "")
	}
	return sanitizedEndpoint, scheme

}

var _ component.Config = (*Config)(nil)
