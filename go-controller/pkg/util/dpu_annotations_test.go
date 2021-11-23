package util

import (
	"encoding/json"
	"fmt"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/kube/mocks"
	"github.com/stretchr/testify/mock"

	. "github.com/onsi/ginkgo"
	"github.com/onsi/gomega"
)

var _ = Describe("DPU Annotations test", func() {
	Describe("DPUConnectionDetails", func() {
		var cd DPUConnectionDetails
		var annot map[string]string
		t := GinkgoT()

		BeforeEach(func() {
			cd = DPUConnectionDetails{}
			annot = make(map[string]string)
		})

		Context("FromPodAnnotation()", func() {
			It("Is populated correctly from annotations", func() {
				annot[DPUConnectionDetailsAnnot] = `{"pfId": "0", "vfId": "3", "sandboxId": "35b82dbe2c3976"}`
				err := cd.FromPodAnnotation(annot)
				gomega.Expect(err).ToNot(gomega.HaveOccurred())
				gomega.Expect(cd.PfId).To(gomega.Equal("0"))
				gomega.Expect(cd.VfId).To(gomega.Equal("3"))
				gomega.Expect(cd.SandboxId).To(gomega.Equal(
					"35b82dbe2c3976"))
			})

			It("Fails to populate on missing annotations", func() {
				err := cd.FromPodAnnotation(annot)
				gomega.Expect(err).To(gomega.HaveOccurred())
			})
		})

		Context("SetPodAnnotation()", func() {
			var fakeAnnotator *mocks.Annotator

			BeforeEach(func() {
				fakeAnnotator = &mocks.Annotator{}
			})

			It("Sets correct Pod annotation", func() {
				cd.PfId = "1"
				cd.VfId = "4"
				cd.SandboxId = "35b82dbe2c3976"
				expected, err := json.Marshal(cd)
				gomega.Expect(err).ToNot(gomega.HaveOccurred())
				fakeAnnotator.On("Set", DPUConnectionDetailsAnnot, string(expected)).Return(nil)
				err = cd.SetPodAnnotation(fakeAnnotator)
				gomega.Expect(err).ToNot(gomega.HaveOccurred())
				fakeAnnotator.AssertExpectations(t)
			})

			It("Fails if pod annotator fails", func() {
				cd.PfId = "1"
				cd.VfId = "4"
				cd.SandboxId = "35b82dbe2c3976"
				fakeAnnotator.On("Set", DPUConnectionDetailsAnnot, mock.Anything).Return(fmt.Errorf("error"))
				err := cd.SetPodAnnotation(fakeAnnotator)
				gomega.Expect(err).To(gomega.HaveOccurred())
			})
		})

		Context("AsAnnotation()", func() {
			It("Should return annotation which allows to create a correct DPUConnectionDetails object", func() {
				cd.PfId = "1"
				cd.VfId = "4"
				cd.SandboxId = "35b82dbe2c3976"
				podAnnot, err := cd.AsAnnotation()
				gomega.Expect(err).ToNot(gomega.HaveOccurred())
				newCd := DPUConnectionDetails{}
				err = newCd.FromPodAnnotation(podAnnot)
				gomega.Expect(cd).To(gomega.Equal(newCd))
			})
		})
	})

	Describe("DPUConnectionStatus", func() {
		var cs DPUConnectionStatus
		var annot map[string]string
		t := GinkgoT()

		BeforeEach(func() {
			cs = DPUConnectionStatus{}
			annot = make(map[string]string)
		})

		Context("FromPodAnnotation()", func() {
			It("Is populated correctly from annotations", func() {
				annot[DPUConnetionStatusAnnot] = `{"status": "Ready"}`
				err := cs.FromPodAnnotation(annot)
				gomega.Expect(err).ToNot(gomega.HaveOccurred())
				gomega.Expect(cs.Status).To(gomega.Equal("Ready"))
				gomega.Expect(cs.Reason).To(gomega.Equal(""))
			})

			It("Is populated with optional Reason from annotations", func() {
				annot[DPUConnetionStatusAnnot] = `{"status": "Error", "reason": "bad-things-happened"}`
				err := cs.FromPodAnnotation(annot)
				gomega.Expect(err).ToNot(gomega.HaveOccurred())
				gomega.Expect(cs.Status).To(gomega.Equal("Error"))
				gomega.Expect(cs.Reason).To(gomega.Equal("bad-things-happened"))
			})

			It("Fails to populate on missing annotations", func() {
				err := cs.FromPodAnnotation(annot)
				gomega.Expect(err).To(gomega.HaveOccurred())
			})
		})

		Context("SetPodAnnotation()", func() {
			var fakeAnnotator *mocks.Annotator

			BeforeEach(func() {
				fakeAnnotator = &mocks.Annotator{}
			})

			It("Sets correct Pod annotation", func() {
				cs.Status = "Ready"
				expected, err := json.Marshal(cs)
				gomega.Expect(err).ToNot(gomega.HaveOccurred())
				fakeAnnotator.On("Set", DPUConnetionStatusAnnot, string(expected)).Return(nil)
				err = cs.SetPodAnnotation(fakeAnnotator)
				gomega.Expect(err).ToNot(gomega.HaveOccurred())
				fakeAnnotator.AssertExpectations(t)
			})

			It("Fails if pod annotator fails", func() {
				cs.Status = "Ready"
				fakeAnnotator.On("Set", DPUConnetionStatusAnnot, mock.Anything).Return(fmt.Errorf("error"))
				err := cs.SetPodAnnotation(fakeAnnotator)
				gomega.Expect(err).To(gomega.HaveOccurred())
			})
		})

		Context("AsAnnotation()", func() {
			It("Should return annotation which allows to create a correct DPUConnectionDetails object", func() {
				cs.Status = "Ready"
				podAnnot, err := cs.AsAnnotation()
				gomega.Expect(err).ToNot(gomega.HaveOccurred())
				newCs := DPUConnectionStatus{}
				err = newCs.FromPodAnnotation(podAnnot)
				gomega.Expect(cs).To(gomega.Equal(newCs))
			})
		})
	})
})
