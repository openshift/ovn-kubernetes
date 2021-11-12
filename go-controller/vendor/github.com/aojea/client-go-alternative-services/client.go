package alternative

import (
	"net/http"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

func NewForConfig(c *rest.Config) (*kubernetes.Clientset, error) {
	config := *c
	fn := func(rt http.RoundTripper) http.RoundTripper {
		return NewAlternativeServiceRoundTripperWithOptions(rt,
			WithLocalhostAllowed(),
			WithActivePolling(),
		)
	}
	config.Wrap(fn)
	return kubernetes.NewForConfig(&config)
}

// NewForConfigOrDie creates a new Clientset for the given config and
// panics if there is an error in the config.
func NewForConfigOrDie(c *rest.Config) *kubernetes.Clientset {
	cs, err := NewForConfig(c)
	if err != nil {
		panic(err)
	}
	return cs
}

func NewForConfigWithAlternativeServices(c *rest.Config, hosts []string) (*kubernetes.Clientset, error) {
	config := *c
	fn := func(rt http.RoundTripper) http.RoundTripper {
		return NewAlternativeServiceRoundTripperWithOptions(rt,
			WithAlternativeServices(hosts),
			WithLocalhostAllowed(),
		)
	}
	config.Wrap(fn)
	return kubernetes.NewForConfig(&config)
}
