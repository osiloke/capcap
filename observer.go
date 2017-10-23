package capcap

import (
	"sync"
	"time"
)

var (
	events          = make([]chan interface{}, 1)
	observerRwMutex sync.RWMutex
)

type NetworkEvent struct {
	Name      string
	WorkerID  string
	Interface string
	Value     interface{}
}

func Subscribe(outputChan chan interface{}) int {
	observerRwMutex.Lock()
	events = append(events, outputChan)
	id := len(events)
	observerRwMutex.Unlock()
	return id
}

// Stop observing the specified event on all channels
func UnSubscribe(id int) error {
	observerRwMutex.Lock()
	defer observerRwMutex.Unlock()
	close(events[id])
	events = append(events[:id], events[id+1:]...)
	return nil
}

// Stop observing the specified event on all channels
func UnSubscribeAll(event string) error {
	observerRwMutex.Lock()
	defer observerRwMutex.Unlock()

	for _, ch := range events {
		close(ch)
	}
	events = make([]chan interface{}, 1)

	return nil
}

func publish(data interface{}) error {
	observerRwMutex.RLock()
	defer observerRwMutex.RUnlock()

	// notify all through chan
	for _, outputChan := range events {
		outputChan <- data
	}

	return nil
}

func PublishTimeout(event string, data interface{}, timeout time.Duration) error {
	observerRwMutex.RLock()
	defer observerRwMutex.RUnlock()

	for _, outputChan := range events {
		select {
		case outputChan <- data:
		case <-time.After(timeout):
		}
	}

	return nil
}
