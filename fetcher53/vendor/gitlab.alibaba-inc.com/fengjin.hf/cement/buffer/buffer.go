package buffer

import (
	"errors"
	"fmt"
)

type InputBuffer struct {
	pos     uint
	data    []byte
	datalen uint
}

func NewInputBuffer(bytes []byte) *InputBuffer {
	buf := &InputBuffer{}
	buf.SetData(bytes)
	return buf
}

func (buf *InputBuffer) SetData(bytes []byte) {
	buf.pos = 0
	buf.data = bytes
	buf.datalen = uint(len(bytes))
}

func (buf *InputBuffer) Len() uint {
	return buf.datalen
}

func (buf *InputBuffer) Position() uint {
	return buf.pos
}

func (buf *InputBuffer) SetPosition(p uint) error {
	if p > buf.datalen {
		return errors.New("buffer overflow")
	}
	buf.pos = p
	return nil
}

func (buf *InputBuffer) ReadUint8() (uint8, error) {
	if buf.pos+1 > buf.datalen {
		return 0, errors.New("read beyond end of buffer")
	}

	b := buf.data[buf.pos]
	buf.pos += 1
	return uint8(b), nil
}

func (buf *InputBuffer) ReadUint16() (uint16, error) {
	if buf.pos+2 > buf.datalen {
		return 0, errors.New("read beyond end of buffer")
	}

	p := buf.pos
	short := uint16(buf.data[p]) << 8
	short |= uint16(buf.data[p+1])
	buf.pos += 2
	return uint16(short), nil
}

func (buf *InputBuffer) ReadUint32() (uint32, error) {
	if buf.pos+4 > buf.datalen {
		return 0, errors.New("read beyond end of buffer")
	}

	p := buf.pos
	i := uint32(buf.data[p]) << 24
	i |= uint32(buf.data[p+1]) << 16
	i |= uint32(buf.data[p+2]) << 8
	i |= uint32(buf.data[p+3])
	buf.pos += 4
	return i, nil
}

func (buf *InputBuffer) ReadBytes(length uint) ([]byte, error) {
	if buf.pos+length > buf.datalen {
		return nil, errors.New("read beyond end of buffer")
	}

	p := buf.pos
	data := buf.data[p : p+length]
	buf.pos += length
	return data, nil
}

func (buf *InputBuffer) ReadVariableLenBytes() ([]byte, error) {
	b0, err := buf.ReadUint8()
	if err != nil {
		return nil, err
	}

	var byteCount int
	switch b0 & 7 {
	case 7:
		byteCount = 4
	case 3:
		byteCount = 3
	case 1, 5:
		byteCount = 2
	default:
		byteCount = 1
	}

	if l, err := buf.readVariableLen(b0, byteCount); err == nil {
		return buf.ReadBytes(l)
	} else {
		return nil, err
	}
}

func (buf *InputBuffer) readVariableLen(firstByte uint8, byteCount int) (uint, error) {
	l := uint(firstByte) >> byteCount
	shift := 8 - byteCount
	for i := 1; i < byteCount; i++ {
		b, err := buf.ReadUint8()
		if err != nil {
			return 0, err
		}
		l |= uint(b) << shift
		shift += 8
	}
	return l, nil
}

type OutputBuffer struct {
	data     []uint8
	capacity int
}

func NewOutputBuffer(capacity int) *OutputBuffer {
	return &OutputBuffer{
		data:     make([]uint8, 0, capacity),
		capacity: capacity,
	}
}

func (out *OutputBuffer) Len() int {
	return len(out.data)
}

func (out *OutputBuffer) Capacity() int {
	return out.capacity
}

func (out *OutputBuffer) Data() []uint8 {
	return out.data
}

func (out *OutputBuffer) At(pos int) (uint8, error) {
	if pos < out.Len() {
		return out.data[pos], nil
	} else {
		return 0, errors.New("out of range")
	}
}

func (out *OutputBuffer) Skip(length int) error {
	l := out.Len() + length
	if l < out.capacity {
		out.data = append(out.data, make([]uint8, length)...)
		return nil
	} else {
		return errors.New("skip out of range")
	}
}

func (out *OutputBuffer) Truncate(newLen int) error {
	if newLen < out.Len() {
		out.data = out.data[0:newLen]
		return nil
	} else {
		return errors.New("new length is larger than original buffer")
	}
}

func (out *OutputBuffer) Resize(new_capacity int) {
	if out.capacity < new_capacity {
		d := make([]uint8, new_capacity)
		copy(d, out.data)
		out.data = d
		out.capacity = new_capacity
	}
}

func (out *OutputBuffer) Clear() {
	out.data = out.data[:0]
}

func (out *OutputBuffer) WriteUint8(data uint8) error {
	if out.Len()+1 <= out.capacity {
		out.data = append(out.data, data)
		return nil
	} else {
		return errors.New("write u8 out of range")
	}
}

func (out *OutputBuffer) WriteUint8At(pos int, data uint8) error {
	if pos < out.Len() {
		out.data[pos] = data
		return nil
	} else {
		return errors.New("write at invalid pos")
	}
}

func (out *OutputBuffer) WriteUint16(data uint16) error {
	if out.Len()+2 <= out.capacity {
		out.data = append(out.data, uint8((data&0xff00)>>8), uint8(data&0x00ff))
		return nil
	} else {
		return errors.New("write u16 out of range")
	}
}

func (out *OutputBuffer) WriteUint16At(pos int, data uint16) error {
	if pos+1 < out.Len() {
		out.data[pos] = uint8((data & 0xff00) >> 8)
		out.data[pos+1] = uint8(data & 0x00ff)
		return nil
	} else {
		return errors.New("write at invalid pos")
	}
}

func (out *OutputBuffer) WriteUint32(data uint32) error {
	if out.Len()+4 <= out.capacity {
		out.data = append(out.data,
			uint8((data&0xff000000)>>24),
			uint8((data&0x00ff0000)>>16),
			uint8((data&0x0000ff00)>>8),
			uint8(data&0x000000ff))
		return nil
	} else {
		return errors.New("write u32 out of range")
	}
}

func (out *OutputBuffer) WriteData(data []uint8) error {
	if out.Len()+len(data) <= out.capacity {
		out.data = append(out.data, data...)
		return nil
	} else {
		return errors.New("write data out of range")
	}
}

func (out *OutputBuffer) LeftSpace() int {
	return out.capacity - out.Len()
}

func (out *OutputBuffer) WriteVariableLenBytes(data []uint8) error {
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
		return fmt.Errorf("slice is too long %d which is bigger than 268435455", n)
	}
	d := [4]byte{
		byte(n), byte(n >> 8), byte(n >> 16), byte(n >> 24),
	}
	if err := out.WriteData(d[:byteCount]); err != nil {
		return err
	} else {
		return out.WriteData(data)
	}
}
