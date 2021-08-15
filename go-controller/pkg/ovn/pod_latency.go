// Copyright 2020 The Kube-burner Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ovn

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strings"
	"sync"
	"time"

	"k8s.io/klog/v2"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

type podMetric struct {
	Timestamp              time.Time `json:"timestamp"`
	scheduled              time.Time
	SchedulingLatency      int `json:"schedulingLatency"`
	initialized            time.Time
	InitializedLatency     int `json:"initializedLatency"`
	containersReady        time.Time
	ContainersReadyLatency int `json:"containersReadyLatency"`
	podReady               time.Time
	PodReadyLatency        int    `json:"podReadyLatency"`
	MetricName             string `json:"metricName"`
	Namespace              string `json:"namespace"`
	Name                   string `json:"podName"`
}

type podLatencyQuantiles struct {
	QuantileName v1.PodConditionType `json:"quantileName"`
	P99          int                 `json:"P99"`
	P95          int                 `json:"P95"`
	P50          int                 `json:"P50"`
	Max          int                 `json:"max"`
	Avg          int                 `json:"avg"`
	Timestamp    time.Time           `json:"timestamp"`
	MetricName   string              `json:"metricName"`
}

var podQuantiles []interface{}
var normLatencies []interface{}
var podMetrics map[string]podMetric
var mutex sync.RWMutex

const (
	informerTimeout                = time.Minute
	podLatencyMeasurement          = "podLatencyMeasurement"
	podLatencyQuantilesMeasurement = "podLatencyQuantilesMeasurement"
)

type podLatency struct {
	informer    cache.SharedInformer
	stopChannel <-chan struct{}
}

var pLatency *podLatency

func newPodLatency() *podLatency {
	return &podLatency{}
}

func (p *podLatency) createPod(obj interface{}) {
	pod := obj.(*v1.Pod)
	mutex.Lock()
	defer mutex.Unlock()
	if _, exists := podMetrics[string(pod.UID)]; !exists {
		if !strings.HasPrefix(pod.Namespace, "openshift-") && pod.Namespace != "default" && pod.Namespace != "kube-system" {
			podMetrics[string(pod.UID)] = podMetric{
				Timestamp:  time.Now().UTC(),
				Namespace:  pod.Namespace,
				Name:       pod.Name,
				MetricName: podLatencyMeasurement,
			}
		}
	}
}

func (p *podLatency) updatePod(obj interface{}) {
	pod := obj.(*v1.Pod)
	mutex.Lock()
	defer mutex.Unlock()
	if pm, exists := podMetrics[string(pod.UID)]; exists && pm.podReady.IsZero() {
		for _, c := range pod.Status.Conditions {
			if c.Status == v1.ConditionTrue {
				switch c.Type {
				case v1.PodScheduled:
					if pm.scheduled.IsZero() {
						pm.scheduled = time.Now().UTC()
					}
				case v1.PodInitialized:
					if pm.initialized.IsZero() {
						pm.initialized = time.Now().UTC()
					}
				case v1.ContainersReady:
					if pm.containersReady.IsZero() {
						pm.containersReady = time.Now().UTC()
					}
				case v1.PodReady:
					pm.podReady = time.Now().UTC()
					klog.Infof("@@@@@ [%s/%s] pod is ready after %vs", pod.Namespace, pod.Name, int(pm.podReady.Sub(pm.Timestamp).Seconds()))
				}
			}
		}
		podMetrics[string(pod.UID)] = pm
	}
}

// Start starts podLatency measurement
func (p *podLatency) start(clientset *kubernetes.Clientset, stopChan <-chan struct{}) {
	podMetrics = make(map[string]podMetric)
	klog.Infof("Creating Pod latency informer")
	podListWatcher := cache.NewFilteredListWatchFromClient(clientset.CoreV1().RESTClient(), "pods", v1.NamespaceAll, func(options *metav1.ListOptions) {})
	p.informer = cache.NewSharedInformer(podListWatcher, nil, 0)
	p.stopChannel = stopChan
	p.informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: p.createPod,
		UpdateFunc: func(oldObj, newObj interface{}) {
			p.updatePod(newObj)
		},
	})
	if err := p.startAndSync(); err != nil {
		klog.Errorf("Pod Latency measurement error: %s", err)
	}
	go func() {
		for {
			select {
			case <-time.After(1 * time.Minute):
				normalizeMetrics()
				calcQuantiles()
				_ = p.writeToFile()
			case <-stopChan:
				return
			}
		}
	}()
}

func (p *podLatency) writeToFile() error {
	filesMetrics := map[string]interface{}{
//		fmt.Sprintf("podLatency.json"):         normLatencies,
		fmt.Sprintf("podLatency-summary.json"): podQuantiles,
	}
	for filename, data := range filesMetrics {
		bytes, err := json.MarshalIndent(data, "", "    ")
		if err != nil {
			klog.Warningf("failed to marshal podLatency file %s", filename)
		} else {
			klog.Infof("@@@@@ [%s] %s", filename, string(bytes))
		}
	}
	return nil
}

// startAndSync starts informer and waits for it to be synced.
func (p *podLatency) startAndSync() error {
	go p.informer.Run(p.stopChannel)
	timeoutCh := make(chan struct{})
	timeoutTimer := time.AfterFunc(informerTimeout, func() {
		close(timeoutCh)
	})
	defer timeoutTimer.Stop()
	if !cache.WaitForCacheSync(timeoutCh, p.informer.HasSynced) {
		return fmt.Errorf("Pod-latency: Timed out waiting for caches to sync")
	}
	return nil
}

// Stop stops podLatency measurement
func (p *podLatency) stop() error {
	normalizeMetrics()
	calcQuantiles()
	timeoutCh := make(chan struct{})
	timeoutTimer := time.AfterFunc(informerTimeout, func() {
		close(timeoutCh)
	})
	defer timeoutTimer.Stop()
	if !cache.WaitForCacheSync(timeoutCh, p.informer.HasSynced) {
		return fmt.Errorf("Pod-latency: Timed out waiting for caches to sync")
	}
	if err := p.writeToFile(); err != nil {
		klog.Errorf("Error writing measurement podLatency: %s", err)
	}
	return nil
}

func normalizeMetrics() {
	mutex.Lock()
	defer mutex.Unlock()
	for _, m := range podMetrics {
		// If a does not reach the Running state (this timestamp wasn't set), we skip that pod
		if m.podReady.IsZero() {
			continue
		}
		m.SchedulingLatency = int(m.scheduled.Sub(m.Timestamp).Milliseconds())
		m.ContainersReadyLatency = int(m.containersReady.Sub(m.Timestamp).Milliseconds())
		m.InitializedLatency = int(m.initialized.Sub(m.Timestamp).Milliseconds())
		m.PodReadyLatency = int(m.podReady.Sub(m.Timestamp).Milliseconds())
		normLatencies = append(normLatencies, m)
	}
}

func calcQuantiles() {
	quantiles := []float64{0.5, 0.95, 0.99}
	quantileMap := map[v1.PodConditionType][]int{}
	for _, normLatency := range normLatencies {
		quantileMap[v1.PodScheduled] = append(quantileMap[v1.PodScheduled], normLatency.(podMetric).SchedulingLatency)
		quantileMap[v1.ContainersReady] = append(quantileMap[v1.ContainersReady], normLatency.(podMetric).ContainersReadyLatency)
		quantileMap[v1.PodInitialized] = append(quantileMap[v1.PodInitialized], normLatency.(podMetric).InitializedLatency)
		quantileMap[v1.PodReady] = append(quantileMap[v1.PodReady], normLatency.(podMetric).PodReadyLatency)
	}
	podQuantiles = make([]interface{}, 0, 5)
	for quantileName, v := range quantileMap {
		podQ := podLatencyQuantiles{
			QuantileName: quantileName,
			Timestamp:    time.Now().UTC(),
			MetricName:   podLatencyQuantilesMeasurement,
		}
		sort.Ints(v)
		length := len(v)
		if length > 1 {
			for _, quantile := range quantiles {
				qValue := v[int(math.Ceil(float64(length)*quantile))-1]
				podQ.setQuantile(quantile, qValue)
			}
			podQ.Max = v[length-1]
		}
		sum := 0
		for _, n := range v {
			sum += n
		}
		podQ.Avg = int(math.Round(float64(sum) / float64(length)))
		podQuantiles = append(podQuantiles, podQ)
	}
}

func (plq *podLatencyQuantiles) setQuantile(quantile float64, qValue int) {
	switch quantile {
	case 0.5:
		plq.P50 = qValue
	case 0.95:
		plq.P95 = qValue
	case 0.99:
		plq.P99 = qValue
	}
}
