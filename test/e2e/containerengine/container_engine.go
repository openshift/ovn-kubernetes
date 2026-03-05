package containerengine

import (
	"fmt"
	"os"
	"strings"
)

// ContainerInspect represents the JSON output from 'docker/podman inspect'
// for a container.
type ContainerInspect struct {
	NetworkSettings struct {
		Networks map[string]EndpointSettings `json:"Networks"`
	} `json:"NetworkSettings"`
}

type EndpointSettings struct {
	Gateway             string `json:"Gateway"`
	IPAddress           string `json:"IPAddress"`
	IPPrefixLen         int    `json:"IPPrefixLen"`
	IPv6Gateway         string `json:"IPv6Gateway"`
	GlobalIPv6Address   string `json:"GlobalIPv6Address"`
	GlobalIPv6PrefixLen int    `json:"GlobalIPv6PrefixLen"`
	MacAddress          string `json:"MacAddress"`
}

type ContainerEngine string

func (ce ContainerEngine) String() string {
	return string(ce)
}

const (
	Docker ContainerEngine = "docker"
	Podman ContainerEngine = "podman"
)

var engine ContainerEngine

func init() {
	if cr, found := os.LookupEnv("CONTAINER_RUNTIME"); found {
		switch strings.ToLower(cr) {
		case Docker.String():
			engine = Docker
		case Podman.String():
			engine = Podman
		default:
			panic(fmt.Sprintf("unknown container engine %q. Supported engines are docker or podman.", cr))
		}
	} else {
		engine = Docker
	}
}

func Get() ContainerEngine {
	if engine.String() == "" {
		panic("container engine is not set")
	}
	return engine
}
