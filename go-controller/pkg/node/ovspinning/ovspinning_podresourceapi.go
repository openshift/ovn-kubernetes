package ovspinning

import (
	"context"
	"fmt"
	"google.golang.org/grpc/credentials/insecure"
	"path/filepath"

	"google.golang.org/grpc"

	podresourcesapi "k8s.io/kubelet/pkg/apis/podresources/v1"
	"k8s.io/utils/cpuset"
)

type PodResClient struct {
	conn   *grpc.ClientConn
	client podresourcesapi.PodResourcesListerClient
}

// New initializes a new podresources client with the given socket path.
func New(socket string) (*PodResClient, error) {
	socketPath := fmt.Sprintf("unix://%s", filepath.Clean(socket))

	conn, err := grpc.NewClient(socketPath, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("failed to connect to podresources socket: %w", err)
	}

	client := podresourcesapi.NewPodResourcesListerClient(conn)
	return &PodResClient{conn: conn, client: client}, nil
}

// Close closes the gRPC connection
func (c *PodResClient) Close() error {
	return c.conn.Close()
}

// Client PodResClient returns the underlying PodResourcesListerClient
func (c *PodResClient) Client() podresourcesapi.PodResourcesListerClient {
	return c.client
}

// GetNonPinnedCPUs calculates and returns all allocatable CPUs on the node which are not
// exclusively pinned to any container. IOW it returns the CPUs that are dedicated for
// Burstable and BestEffort QoS containers
func (c *PodResClient) GetNonPinnedCPUs(ctx context.Context) (cpuset.CPUSet, error) {
	// Get allocatable CPUs
	allocatableResp, err := c.client.GetAllocatableResources(ctx, &podresourcesapi.AllocatableResourcesRequest{})
	if err != nil {
		return cpuset.CPUSet{}, fmt.Errorf("GetAllocatableResources failed: %w", err)
	}
	allocatableCPUs := cpuset.New(convertInt64ToInt(allocatableResp.CpuIds)...)

	// List pod resources and collect used CPUs
	listResp, err := c.client.List(ctx, &podresourcesapi.ListPodResourcesRequest{})
	if err != nil {
		return cpuset.CPUSet{}, fmt.Errorf("ListPodResources failed: %w", err)
	}

	usedCPUs := cpuset.New()
	for _, pod := range listResp.PodResources {
		for _, container := range pod.Containers {
			usedCPUs = usedCPUs.Union(cpuset.New(convertInt64ToInt(container.CpuIds)...))
		}
	}

	// Calculate the difference
	availableCPUs := allocatableCPUs.Difference(usedCPUs)
	return availableCPUs, nil
}

func convertInt64ToInt(int64s []int64) []int {
	ints := make([]int, len(int64s))
	for i, v := range int64s {
		ints[i] = int(v)
	}
	return ints
}
