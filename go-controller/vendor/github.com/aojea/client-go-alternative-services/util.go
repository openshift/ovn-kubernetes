package alternative

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilnet "k8s.io/apimachinery/pkg/util/net"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"
)

func tryCancelRequest(rt http.RoundTripper, req *http.Request) {
	type canceler interface {
		CancelRequest(*http.Request)
	}
	switch rt := rt.(type) {
	case canceler:
		rt.CancelRequest(req)
	case utilnet.RoundTripperWrapper:
		tryCancelRequest(rt.WrappedRoundTripper(), req)
	default:
		klog.Warningf("Unable to cancel request for %T", rt)
	}
}

// CloneRequest creates a shallow copy of the request along with a deep copy of the Headers.
func CloneRequest(req *http.Request) *http.Request {
	r := new(http.Request)

	// shallow clone
	*r = *req

	r.URL = CloneURL(req.URL)
	// deep copy headers
	r.Header = CloneHeader(req.Header)

	return r
}

// CloneHeader creates a deep copy of an http.Header.
func CloneHeader(in http.Header) http.Header {
	out := make(http.Header, len(in))
	for key, values := range in {
		newValues := make([]string, len(values))
		copy(newValues, values)
		out[key] = newValues
	}
	return out
}

// CloneURL creates a deep copy of an URL
// https://github.com/golang/go/blob/2ebe77a2fda1ee9ff6fd9a3e08933ad1ebaea039/src/net/http/clone.go#L22
func CloneURL(u *url.URL) *url.URL {
	if u == nil {
		return nil
	}
	u2 := new(url.URL)
	*u2 = *u
	if u.User != nil {
		u2.User = new(url.Userinfo)
		*u2.User = *u.User
	}
	return u2
}

// return the unique endpoint IPs
func getEndpointIPs(endpoints *v1.Endpoints) []string {
	ips := make([]string, 0)
	if endpoints == nil || len(endpoints.Subsets) == 0 {
		return ips
	}
	for _, subset := range endpoints.Subsets {
		for _, address := range subset.Addresses {
			ips = append(ips, address.IP)
		}
	}
	return ips
}

func generateAltSvc(ips []string) string {
	// Generate Alt-Svc header
	// ref: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Alt-Svc
	// Example: h2="10.0.0.2:6443", h2="10.0.0.3:6443", h2="10.0.0.4:6443"
	var hdr string
	for i, a := range ips {
		if i != 0 {
			hdr += ", "
		}
		hdr += fmt.Sprintf(`h2="%s"`, net.JoinHostPort(a, "6443"))
	}
	return hdr
}

// getAPIServerEndpoints polls the API server and returns its endpoints as an Alt-Svc header
func getAPIServerEndpoints(base *url.URL, client *http.Client) (string, error) {
	versionedAPIPath := "/api/v1"
	gv := v1.SchemeGroupVersion
	content := rest.ClientContentConfig{
		AcceptContentTypes: "application/json",
		ContentType:        "application/json",
		GroupVersion:       gv,
		Negotiator:         runtime.NewClientNegotiator(scheme.Codecs.WithoutConversion(), gv),
	}

	r := rest.NewRequestWithClient(base, versionedAPIPath, content, client)
	endpoint := &v1.Endpoints{}
	req := r.Verb("GET").
		Resource("endpoints").
		Namespace("default").
		Name("kubernetes")
	klog.V(4).InfoS("Request kubernetes.default endpoints", "request", req)
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(3*time.Second))
	defer cancel()
	err := req.Do(ctx).Into(endpoint)
	if err != nil {
		return "", err
	}

	ips := getEndpointIPs(endpoint)
	return generateAltSvc(ips), nil
}
