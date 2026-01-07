package netprobe

import (
	"sync"

	"github.com/elliotchance/orderedmap/v2"
)

type SafeOrderedMap[K comparable, V any] struct {
	orderedmap orderedmap.OrderedMap[K, V]
	mutex      sync.RWMutex
}

type KeyValuePair[K comparable, V any] struct {
	Key   K
	Value V
}

func NewSafeOrderedMap[K comparable, V any]() *SafeOrderedMap[K, V] {
	return &SafeOrderedMap[K, V]{
		orderedmap: *orderedmap.NewOrderedMap[K, V](),
	}
}

func (this *SafeOrderedMap[K, V]) Front() (key K, value V, ok bool) {
	this.mutex.RLock()
	defer this.mutex.RUnlock()
	temp := this.orderedmap.Front()
	if temp != nil {
		return temp.Key, temp.Value, true
	} else {
		var k K
		var v V
		return k, v, false
	}
}

func (this *SafeOrderedMap[K, V]) Set(key K, value V) (newElement bool) {
	this.mutex.Lock()
	defer this.mutex.Unlock()
	return this.orderedmap.Set(key, value)
}

func (this *SafeOrderedMap[K, V]) Get(key K) (value V, ok bool) {
	this.mutex.Lock()
	defer this.mutex.Unlock()
	return this.orderedmap.Get(key)
}

func (this *SafeOrderedMap[K, V]) Delete(key K) (didDelete bool) {
	this.mutex.Lock()
	defer this.mutex.Unlock()
	return this.orderedmap.Delete(key)
}
