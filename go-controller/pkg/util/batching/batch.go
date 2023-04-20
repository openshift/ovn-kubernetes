package batching

import (
	"fmt"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/nbdb"
)

func Batch(batchSize int, data []nbdb.ACL, eachFn func([]nbdb.ACL) error) error {
	if batchSize < 1 {
		return fmt.Errorf("batchSize should be > 0, got %d", batchSize)
	}
	start := 0
	dataLen := len(data)
	for start < dataLen {
		end := start + batchSize
		if end > dataLen {
			end = dataLen
		}
		err := eachFn(data[start:end])
		if err != nil {
			return err
		}
		start = end
	}
	return nil
}
