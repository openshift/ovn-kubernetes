package pool_test

import (
	"net"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util/pool"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("NetworkPool", func() {
	const testNetwork = "test-network"
	const ownerID1 = "namespace1/pod1"
	const ownerID2 = "namespace2/pod2"

	var testPool *pool.NetworkPool
	var testMAC1, testMAC2 net.HardwareAddr

	BeforeEach(func() {
		var err error
		testMAC1, err = net.ParseMAC("aa:bb:cc:dd:ee:f1")
		Expect(err).NotTo(HaveOccurred())
		testMAC2, err = net.ParseMAC("aa:bb:cc:dd:ee:f2")
		Expect(err).NotTo(HaveOccurred())
		testPool = pool.NewNetworkPool()
	})

	Describe("MAC Pool Operations", func() {
		Context("when adding MACs to pool", func() {
			It("should handle nil MAC gracefully", func() {
				testPool.AddMACToPool(testNetwork, nil, ownerID1)

				Expect(testPool.GetMACPoolStats(testNetwork)).To(BeZero())
			})
			It("should successfully add MAC to pool", func() {
				testPool.AddMACToPool(testNetwork, testMAC1, ownerID1)

				Expect(testPool.IsMACConflict(testNetwork, testMAC1, ownerID2)).To(BeTrue())
			})
			It("should allow adding same MAC multiple times without duplicates", func() {
				testPool.AddMACToPool(testNetwork, testMAC1, ownerID1)
				testPool.AddMACToPool(testNetwork, testMAC1, ownerID1)

				Expect(testPool.IsMACConflict(testNetwork, testMAC1, ownerID2)).To(BeTrue())

				Expect(testPool.GetMACPoolStats(testNetwork)).To(Equal(1),
					"pool should have one element")
			})
			It("should not return MAC conflict for entry of same owner", func() {
				testPool.AddMACToPool(testNetwork, testMAC1, ownerID1)
				Expect(testPool.IsMACConflict(testNetwork, testMAC1, ownerID1)).To(BeFalse(),
					"same owner should not get conflict")
				Expect(testPool.IsMACConflict(testNetwork, testMAC1, ownerID2)).To(BeTrue(),
					"different owner should not get conflict")
			})
			It("should handle multiple MACs in same network", func() {
				testPool.AddMACToPool(testNetwork, testMAC1, ownerID1)
				testPool.AddMACToPool(testNetwork, testMAC2, ownerID1)

				Expect(testPool.IsMACConflict(testNetwork, testMAC1, ownerID2)).To(BeTrue())
				Expect(testPool.IsMACConflict(testNetwork, testMAC2, ownerID2)).To(BeTrue())

				Expect(testPool.GetMACPoolStats(testNetwork)).To(Equal(2),
					"pool should have two elements")
			})
			It("should isolate MACs between different networks", func() {
				const anotherNetwork = "another-network"

				testPool.AddMACToPool(testNetwork, testMAC1, ownerID1)
				testPool.AddMACToPool(anotherNetwork, testMAC2, ownerID1)

				// MAC1 should conflict only in test-network
				Expect(testPool.IsMACConflict(testNetwork, testMAC1, ownerID2)).To(
					BeTrueBecause("mac1 already allocated in testNetwork by owner1"))
				Expect(testPool.IsMACConflict(anotherNetwork, testMAC1, ownerID2)).To(
					BeFalseBecause("mac1 not in use in anotherNetwork"))
				// MAC2 should conflict only in another-network
				Expect(testPool.IsMACConflict(testNetwork, testMAC2, ownerID2)).To(
					BeFalseBecause("mac2 not in use testNetwork"))
				Expect(testPool.IsMACConflict(anotherNetwork, testMAC2, ownerID2)).To(
					BeTrueBecause("mac2 already allocated in anotherNetwork by owner2"))
			})
		})

		Context("when removing MACs from pool", func() {
			It("should handle nil MAC gracefully", func() {
				testPool.RemoveMACFromPool(testNetwork, nil)

				Expect(testPool.GetMACPoolStats(testNetwork)).To(BeZero(), "nit mac is no-op")
			})
			It("should handle removing non-existent MAC gracefully", func() {
				testPool.RemoveMACFromPool(testNetwork, testMAC1)

				Expect(testPool.IsMACConflict(testNetwork, testMAC1, ownerID1)).To(BeFalse())
			})
			It("should handle removing from non-existent network gracefully", func() {
				testPool.RemoveMACFromPool("non-existent-network", testMAC1)

				Expect(testPool.IsMACConflict("non-existent-network", testMAC1, ownerID1)).To(BeFalse())
			})
			It("should successfully remove existing MAC", func() {
				testPool.AddMACToPool(testNetwork, testMAC1, ownerID1)
				testPool.RemoveMACFromPool(testNetwork, testMAC1)

				Expect(testPool.IsMACConflict(testNetwork, testMAC1, ownerID2)).To(BeFalse())

				Expect(testPool.GetMACPoolStats(testNetwork)).To(BeZero(), "pool should remain empty")
			})
		})

		Context("when checking MAC conflicts", func() {
			It("should handle nil MAC gracefully", func() {
				Expect(testPool.IsMACConflict(testNetwork, nil, ownerID1)).To(BeFalse())
			})
			It("should return false for non-existent network", func() {
				Expect(testPool.IsMACConflict("non-existent-network", testMAC1, ownerID1)).To(BeFalse())
			})
			It("should return false for empty pool", func() {
				Expect(testPool.IsMACConflict(testNetwork, testMAC1, ownerID1)).To(BeFalse())
			})
		})
	})
})
