package kind

import (
	"fmt"
	"os"
	"strings"
)

type containerRuntime string

func (ce containerRuntime) String() string {
	return string(ce)
}

const (
	docker containerRuntime = "docker"
	podman containerRuntime = "podman"
)

var engine containerRuntime

func init() {
	if cr, found := os.LookupEnv("CONTAINER_RUNTIME"); found {
		switch strings.ToLower(cr) {
		case docker.String():
			engine = docker
		case podman.String():
			engine = podman
		default:
			panic(fmt.Sprintf("unknown container engine %q. Supported engines are docker or podman.", cr))
		}
	} else {
		engine = docker
	}
}

func getContainerRuntime() containerRuntime {
	if engine.String() == "" {
		panic("container engine is not set")
	}
	return engine
}
