package main

type DataBuff[T any] struct {
	Size     int
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

func (this *DataBuff[T]) Insert(index int, item T) []T {
	ndequeue := len(this.elements) + 1 - this.Size
	if ndequeue < 0 {
		ndequeue = 0
	}

	if index >= len(this.elements) { // nil or empty slice or after last element
		this.elements = append(this.elements, item)[ndequeue:]
	} else {
		temp := append(this.elements[:index+1], this.elements[index:]...) // index < len(a)
		temp[index] = item
		this.elements = temp[ndequeue:]
	}
	return this.elements
}

// This returns a slice, not a copy, so it is important not to mutate the data.
func (this *DataBuff[T]) Snapshot() (items []T) {
	items = this.elements[:]
	return
}

func (this *DataBuff[T]) Len() (length int) {
	length = len(this.elements)
	return
}
