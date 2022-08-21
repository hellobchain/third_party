// Code generated by counterfeiter. DO NOT EDIT.
package metricsfakes

import (
	"sync"

	"github.com/wsw365904/third_party/hyperledger/fabric/common/metrics"
)

type Histogram struct {
	WithStub        func(labelValues ...string) metrics.Histogram
	withMutex       sync.RWMutex
	withArgsForCall []struct {
		labelValues []string
	}
	withReturns struct {
		result1 metrics.Histogram
	}
	withReturnsOnCall map[int]struct {
		result1 metrics.Histogram
	}
	ObserveStub        func(value float64)
	observeMutex       sync.RWMutex
	observeArgsForCall []struct {
		value float64
	}
	invocations      map[string][][]interface{}
	invocationsMutex sync.RWMutex
}

func (fake *Histogram) With(labelValues ...string) metrics.Histogram {
	fake.withMutex.Lock()
	ret, specificReturn := fake.withReturnsOnCall[len(fake.withArgsForCall)]
	fake.withArgsForCall = append(fake.withArgsForCall, struct {
		labelValues []string
	}{labelValues})
	fake.recordInvocation("With", []interface{}{labelValues})
	fake.withMutex.Unlock()
	if fake.WithStub != nil {
		return fake.WithStub(labelValues...)
	}
	if specificReturn {
		return ret.result1
	}
	return fake.withReturns.result1
}

func (fake *Histogram) WithCallCount() int {
	fake.withMutex.RLock()
	defer fake.withMutex.RUnlock()
	return len(fake.withArgsForCall)
}

func (fake *Histogram) WithArgsForCall(i int) []string {
	fake.withMutex.RLock()
	defer fake.withMutex.RUnlock()
	return fake.withArgsForCall[i].labelValues
}

func (fake *Histogram) WithReturns(result1 metrics.Histogram) {
	fake.WithStub = nil
	fake.withReturns = struct {
		result1 metrics.Histogram
	}{result1}
}

func (fake *Histogram) WithReturnsOnCall(i int, result1 metrics.Histogram) {
	fake.WithStub = nil
	if fake.withReturnsOnCall == nil {
		fake.withReturnsOnCall = make(map[int]struct {
			result1 metrics.Histogram
		})
	}
	fake.withReturnsOnCall[i] = struct {
		result1 metrics.Histogram
	}{result1}
}

func (fake *Histogram) Observe(value float64) {
	fake.observeMutex.Lock()
	fake.observeArgsForCall = append(fake.observeArgsForCall, struct {
		value float64
	}{value})
	fake.recordInvocation("Observe", []interface{}{value})
	fake.observeMutex.Unlock()
	if fake.ObserveStub != nil {
		fake.ObserveStub(value)
	}
}

func (fake *Histogram) ObserveCallCount() int {
	fake.observeMutex.RLock()
	defer fake.observeMutex.RUnlock()
	return len(fake.observeArgsForCall)
}

func (fake *Histogram) ObserveArgsForCall(i int) float64 {
	fake.observeMutex.RLock()
	defer fake.observeMutex.RUnlock()
	return fake.observeArgsForCall[i].value
}

func (fake *Histogram) Invocations() map[string][][]interface{} {
	fake.invocationsMutex.RLock()
	defer fake.invocationsMutex.RUnlock()
	fake.withMutex.RLock()
	defer fake.withMutex.RUnlock()
	fake.observeMutex.RLock()
	defer fake.observeMutex.RUnlock()
	copiedInvocations := map[string][][]interface{}{}
	for key, value := range fake.invocations {
		copiedInvocations[key] = value
	}
	return copiedInvocations
}

func (fake *Histogram) recordInvocation(key string, args []interface{}) {
	fake.invocationsMutex.Lock()
	defer fake.invocationsMutex.Unlock()
	if fake.invocations == nil {
		fake.invocations = map[string][][]interface{}{}
	}
	if fake.invocations[key] == nil {
		fake.invocations[key] = [][]interface{}{}
	}
	fake.invocations[key] = append(fake.invocations[key], args)
}

var _ metrics.Histogram = new(Histogram)
