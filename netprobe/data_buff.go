package netprobe

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
	overflow := len(this.elements) + len(items) - this.Size
	if overflow < 0 {
		overflow = 0
	}
	this.elements = append(this.elements, items...)[overflow:]
}

func (this *DataBuff[T]) Insert(index int, item T) []T {
	overflow := len(this.elements) + 1 - this.Size
	if overflow < 0 {
		overflow = 0
	}

	if index >= len(this.elements) { // nil or empty slice or after last element
		this.elements = append(this.elements, item)[overflow:]
	} else {
		temp := append(this.elements[:index+1], this.elements[index:]...) // index < len(a)
		temp[index] = item
		this.elements = temp[overflow:]
	}
	return this.elements
}

// Snapshot returns a slice, not a copy, so it is important not to mutate the data.
func (this *DataBuff[T]) Snapshot() (items []T) {
	items = this.elements[:]
	return
}

func (this *DataBuff[T]) Len() (length int) {
	length = len(this.elements)
	return
}
