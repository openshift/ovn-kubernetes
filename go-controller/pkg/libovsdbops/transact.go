package libovsdbops

import (
	"context"
	"errors"
	"fmt"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/klog/v2"
	"time"

	"github.com/ovn-org/libovsdb/client"
	"github.com/ovn-org/libovsdb/model"
	"github.com/ovn-org/libovsdb/ovsdb"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"
)

// TransactWithRetry will attempt a transaction several times if it receives an error indicating that the client
// was not connected when the transaction occurred.
func TransactWithRetry(ctx context.Context, c client.Client, ops []ovsdb.Operation) ([]ovsdb.OperationResult, error) {
	_, _, _, results, err := TransactWithRetryTime(ctx, c, ops)
	return results, err
}

// TransactWithRetry will attempt a transaction several times if it receives an error indicating that the client
// was not connected when the transaction occurred.
func TransactWithRetryTime(ctx context.Context, c client.Client, ops []ovsdb.Operation) (time.Duration, time.Duration, time.Duration, []ovsdb.OperationResult, error) {
	start := time.Now()
	var results []ovsdb.OperationResult
	var rlockTime, callTime time.Duration
	resultErr := wait.PollImmediateUntilWithContext(ctx, 200*time.Millisecond, func(ctx context.Context) (bool, error) {
		var err error
		rlockTime, callTime, results, err = c.TransactTime(ctx, ops...)
		if err == nil {
			return true, nil
		}
		if err != nil && errors.Is(err, client.ErrNotConnected) {
			klog.V(5).Infof("Unable to execute transaction: %+v. Client is disconnected, will retry...", ops)
			return false, nil
		}
		return false, err
	})
	return time.Since(start), rlockTime, callTime, results, resultErr
}

func TransactAndCheck(c client.Client, ops []ovsdb.Operation) ([]ovsdb.OperationResult, error) {
	_, _, _, results, err := TransactAndCheckTime(c, ops)
	return results, err
}

func TransactAndCheckTime(c client.Client, ops []ovsdb.Operation) (time.Duration, time.Duration, time.Duration, []ovsdb.OperationResult, error) {
	if len(ops) <= 0 {
		return 0, 0, 0, []ovsdb.OperationResult{{}}, nil
	}

	klog.Infof("Configuring OVN: %+v", ops)

	ctx, cancel := context.WithTimeout(context.TODO(), types.OVSDBTimeout)
	defer cancel()

	retryTime, rlockTime, callTime, results, err := TransactWithRetryTime(ctx, c, ops)
	if err != nil {
		return 0, 0, 0, nil, fmt.Errorf("error in transact with ops %+v: %v", ops, err)
	}

	opErrors, err := ovsdb.CheckOperationResults(results, ops)
	if err != nil {
		return 0, 0, 0, nil, fmt.Errorf("error in transact with ops %+v results %+v and errors %+v: %v", ops, results, opErrors, err)
	}

	return retryTime, rlockTime, callTime, results, nil
}

// TransactAndCheckAndSetUUIDs transacts the given ops against client and returns
// results if no error occurred or an error otherwise. It sets the real uuids for
// the passed models if they were inserted and have a named-uuid (as built by
// BuildNamedUUID)
func TransactAndCheckAndSetUUIDs(client client.Client, models interface{}, ops []ovsdb.Operation) ([]ovsdb.OperationResult, error) {
	_, _, _, results, err := TransactAndCheckAndSetUUIDsTime(client, models, ops)
	return results, err
}

// TransactAndCheckAndSetUUIDs transacts the given ops against client and returns
// results if no error occurred or an error otherwise. It sets the real uuids for
// the passed models if they were inserted and have a named-uuid (as built by
// BuildNamedUUID)
func TransactAndCheckAndSetUUIDsTime(client client.Client, models interface{}, ops []ovsdb.Operation) (time.Duration, time.Duration, time.Duration, []ovsdb.OperationResult, error) {
	retryTime, rlockTime, callTime, results, err := TransactAndCheckTime(client, ops)
	if err != nil {
		return 0, 0, 0, nil, err
	}

	namedModelMap := map[string]model.Model{}
	_ = onModels(models, func(model interface{}) error {
		uuid := getUUID(model)
		if isNamedUUID(uuid) {
			namedModelMap[uuid] = model
		}
		return nil
	})

	if len(namedModelMap) == 0 {
		return retryTime, rlockTime, callTime, results, nil
	}

	for i, op := range ops {
		if op.Op != ovsdb.OperationInsert {
			continue
		}

		if !isNamedUUID(op.UUIDName) {
			continue
		}

		if model, ok := namedModelMap[op.UUIDName]; ok {
			setUUID(model, results[i].UUID.GoUUID)
		}
	}

	return retryTime, rlockTime, callTime, results, nil
}
