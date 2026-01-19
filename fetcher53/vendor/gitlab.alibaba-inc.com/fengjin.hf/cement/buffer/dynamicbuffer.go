package buffer

import (
	"fmt"
)

// if init len isn't big enough, we will dynamically grow
// the mem
type DynamicOutputBuffer struct {
	data []uint8
}

func NewDynamicOutputBuffer(capacity int) *DynamicOutputBuffer {
	return &DynamicOutputBuffer{
		data: make([]uint8, 0, capacity),
	}
}

func (o *DynamicOutputBuffer) Len() int {
	return len(o.data)
}

func (o *DynamicOutputBuffer) Capacity() int {
	return cap(o.data)
}

func (o *DynamicOutputBuffer) Data() []uint8 {
	return o.data
}

func (o *DynamicOutputBuffer) At(pos int) uint8 {
	if pos < o.Len() {
		panic(fmt.Sprintf("read at pos %d is out of range %d", pos, o.Len()))
	}
	return o.data[pos]
}

func (o *DynamicOutputBuffer) Skip(length int) {
	o.WriteData(make([]uint8, length))
}

func (o *DynamicOutputBuffer) Truncate(newLen int) {
	if newLen > o.Len() {
		panic(fmt.Sprintf("truncate len %d is out of range %d", newLen, o.Len()))
	}
	o.data = o.data[0:newLen]
}

func (o *DynamicOutputBuffer) Clear() {
	o.data = o.data[:0]
}

func (o *DynamicOutputBuffer) WriteUint8(data uint8) {
	o.data = append(o.data, data)
}

func (o *DynamicOutputBuffer) WriteUint8At(pos int, data uint8) {
	if pos < o.Len() {
		panic(fmt.Sprintf("writeUint8 at pos %d is out of range %d", pos, o.Len()))
	}
	o.data[pos] = data
}

func (o *DynamicOutputBuffer) WriteUint16(data uint16) {
	o.data = append(o.data, uint8((data&0xff00)>>8), uint8(data&0x00ff))
}

func (o *DynamicOutputBuffer) WriteUint16At(pos int, data uint16) {
	if pos+1 >= o.Len() {
		panic(fmt.Sprintf("WriteUint16 at pos %d is out of range %d", pos, o.Len()))
	}
	o.data[pos] = uint8((data & 0xff00) >> 8)
	o.data[pos+1] = uint8(data & 0x00ff)
}

func (o *DynamicOutputBuffer) WriteUint32(data uint32) {
	o.data = append(o.data,
		uint8((data&0xff000000)>>24),
		uint8((data&0x00ff0000)>>16),
		uint8((data&0x0000ff00)>>8),
		uint8(data&0x000000ff))
}

func (out *DynamicOutputBuffer) WriteData(data []uint8) {
	out.data = append(out.data, data...)
}

func (out *DynamicOutputBuffer) WriteVariableLenBytes(data []uint8) {
	n := len(data)
	byteCount := 0
	switch {
	case n < 128:
		byteCount = 1
		n = n << 1
	case n < 16384:
		byteCount = 2
		n = (n << 2) | 1
	case n < 2097152:
		byteCount = 3
		n = (n << 3) | 3
	case n < 268435456:
		byteCount = 4
		n = (n << 4) | 7
	default:
		panic(fmt.Sprintf("slice length %d which is bigger than 268435455", n))
	}
	d := [4]byte{
		byte(n), byte(n >> 8), byte(n >> 16), byte(n >> 24),
	}
	out.WriteData(d[:byteCount])
	out.WriteData(data)
}
