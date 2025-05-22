package ovspinning

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	podresourcesapi "k8s.io/kubelet/pkg/apis/podresources/v1"
	"k8s.io/utils/cpuset"
)

// mockPodResourcesListerClient implements podresourcesapi.PodResourcesListerClient
type mockPodResourcesListerClient struct {
	podresourcesapi.PodResourcesListerClient
	allocatableCPUs []int64
	usedCPUs        [][]int64
}

func (m *mockPodResourcesListerClient) GetAllocatableResources(ctx context.Context, in *podresourcesapi.AllocatableResourcesRequest, opts ...grpc.CallOption) (*podresourcesapi.AllocatableResourcesResponse, error) {
	return &podresourcesapi.AllocatableResourcesResponse{
		CpuIds: m.allocatableCPUs,
	}, nil
}

func (m *mockPodResourcesListerClient) List(ctx context.Context, in *podresourcesapi.ListPodResourcesRequest, opts ...grpc.CallOption) (*podresourcesapi.ListPodResourcesResponse, error) {
	pods := []*podresourcesapi.PodResources{}
	for _, used := range m.usedCPUs {
		pods = append(pods, &podresourcesapi.PodResources{
			Containers: []*podresourcesapi.ContainerResources{
				{CpuIds: used},
			},
		})
	}
	return &podresourcesapi.ListPodResourcesResponse{
		PodResources: pods,
	}, nil
}

func TestGetNonPinnedCPUs(t *testing.T) {
	mockClient := &mockPodResourcesListerClient{
		allocatableCPUs: []int64{0, 1, 2, 3, 4, 5},
		usedCPUs: [][]int64{
			{0, 1},
			{2},
		},
	}

	// We don't need a real gRPC connection for the test
	client := &PodResClient{
		client: mockClient,
	}

	ctx := context.Background()
	nonPinnedCPUs, err := client.GetNonPinnedCPUs(ctx)
	require.NoError(t, err)

	expected := cpuset.New(3, 4, 5)
	assert.True(t, nonPinnedCPUs.Equals(expected), "expected non-pinned CPUs to match")
}
