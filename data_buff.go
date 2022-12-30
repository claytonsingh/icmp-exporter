package main

import (
//	"sync"
//	"fmt"
)

type PDB = DataBuff[PingResult]

type DataBuff[T any] struct {
	Size int
	elements []T
}

func NewDataBuff[T any](Size int) DataBuff[T] {
	var db DataBuff[T]
	db.Size = Size
	return db
}

func (this *DataBuff[T]) Append(items ...T) {
	ndequeue := len(this.elements) + len(items) - this.Size
	if ndequeue < 0 {
		ndequeue = 0
	}
	this.elements = append(this.elements, items...)[ndequeue:]
}

func (this *DataBuff[T]) Snapshot() (items []T)  {
	items = this.elements[:]
	return
}

func (this *DataBuff[T]) Len() (length int)  {
	length = len(this.elements)
	return
}

// func main() {
// 	db := NewDataBuff[int](10)
// 
// 	for i := 10; i < 30; i++ {
// 		db.Append(i, i + 10, i + 20)
// 		fmt.Println(db.elements)
// 	}
// }
