package batching

import (
	"fmt"
	"github.com/onsi/ginkgo"
	"github.com/onsi/gomega"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/nbdb"

	"strings"
	"testing"
)

type batchTestData struct {
	name      string
	batchSize int
	data      []nbdb.ACL
	expectErr string
}

func TestBatch(t *testing.T) {
	acl1 := nbdb.ACL{UUID: "1"}
	acl2 := nbdb.ACL{UUID: "2"}
	acl3 := nbdb.ACL{UUID: "3"}
	acl4 := nbdb.ACL{UUID: "4"}
	acl5 := nbdb.ACL{UUID: "5"}

	tt := []batchTestData{
		{
			name:      "batch size should be > 0",
			batchSize: 0,
			data:      []nbdb.ACL{acl1, acl2, acl3},
			expectErr: "batchSize should be > 0",
		},
		{
			name:      "batchSize = 1",
			batchSize: 1,
			data:      []nbdb.ACL{acl1, acl2, acl3},
		},
		{
			name:      "batchSize > 1",
			batchSize: 2,
			data:      []nbdb.ACL{acl1, acl2, acl3},
		},
		{
			name:      "number of batches = 0",
			batchSize: 2,
			data:      nil,
		},
		{
			name:      "number of batches = 1",
			batchSize: 2,
			data:      []nbdb.ACL{acl1, acl2},
		},
		{
			name:      "number of batches > 1",
			batchSize: 2,
			data:      []nbdb.ACL{acl1, acl2, acl3, acl4},
		},
		{
			name:      "number of batches not int",
			batchSize: 2,
			data:      []nbdb.ACL{acl1, acl2, acl3, acl4, acl5},
		},
	}

	for _, tCase := range tt {
		g := gomega.NewGomegaWithT(t)
		ginkgo.By(tCase.name)
		var result []nbdb.ACL
		batchNum := 0
		err := Batch(tCase.batchSize, tCase.data, func(l []nbdb.ACL) error {

			batchNum += 1
			result = append(result, l...)
			return nil
		})
		if err != nil {
			if tCase.expectErr != "" && strings.Contains(err.Error(), tCase.expectErr) {
				continue
			}
			t.Fatal(fmt.Sprintf("test %s failed: %v", tCase.name, err))
		}
		// tCase.data/tCase.batchSize round up
		expectedBatchNum := (len(tCase.data) + tCase.batchSize - 1) / tCase.batchSize
		g.Expect(batchNum).To(gomega.Equal(expectedBatchNum))
		g.Expect(result).To(gomega.Equal(tCase.data))
	}
}
