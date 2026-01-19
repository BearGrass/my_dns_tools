package g53

import (
	"gitlab.alibaba-inc.com/fengjin.hf/cement/buffer"
)

type offsetItem struct {
	hash uint32
	pos  uint16
	l    uint16
}

type nameComparator struct {
	buf           *buffer.OutputBuffer
	nameBuf       *buffer.InputBuffer
	hash          uint32
	caseSensitive bool
}

func (c *nameComparator) compare(item *offsetItem) bool {
	if item.hash != c.hash || item.l != uint16(c.nameBuf.Len()) {
		return false
	}

	itemPos := item.pos
	itemLabelLen := uint8(0)
	for {
		itemLabelLen, itemPos = nextPos(c.buf, itemPos)
		nameLabelLen, _ := c.nameBuf.ReadUint8()
		if itemLabelLen != nameLabelLen {
			return false
		} else if nameLabelLen == 0 {
			return true
		}

		for nameLabelLen > 0 {
			ch1, _ := c.buf.At(int(itemPos))
			ch2, _ := c.nameBuf.ReadUint8()
			if c.caseSensitive {
				if ch1 != ch2 {
					return false
				}
			} else {
				if maptolower[int(ch1)] != maptolower[int(ch2)] {
					return false
				}
			}
			itemPos++
			nameLabelLen -= 1
		}
	}
}

func nextPos(buf *buffer.OutputBuffer, pos uint16) (uint8, uint16) {
	b, _ := buf.At(int(pos))
	for b&COMPRESS_POINTER_MARK8 == COMPRESS_POINTER_MARK8 {
		nb, _ := buf.At(int(pos + 1))
		pos = uint16((b & ^uint8(COMPRESS_POINTER_MARK8)))*256 + uint16(nb)
		b, _ = buf.At(int(pos))
	}
	return b, pos + 1
}

const (
	BUCKETS        uint   = 64
	RESERVED_ITEMS uint   = 16
	NO_OFFSET      uint16 = 65535
)

type MsgRender struct {
	buf           *buffer.OutputBuffer
	truncated     bool
	caseSensitive bool
	table         [BUCKETS][]offsetItem
	seqHashs      [MAX_LABELS]uint32
}

func NewMsgRender(lenLimit int) *MsgRender {
	render := MsgRender{
		buf:           buffer.NewOutputBuffer(lenLimit),
		truncated:     false,
		caseSensitive: false,
	}
	for i := uint(0); i < BUCKETS; i++ {
		render.table[i] = make([]offsetItem, 0, RESERVED_ITEMS)
	}
	return &render
}

func (r *MsgRender) IsTrancated() bool {
	return r.truncated
}

func (r *MsgRender) SetTrancated() {
	r.truncated = true
}

func (r *MsgRender) findOffset(buf *buffer.OutputBuffer, nameBuf *buffer.InputBuffer, hash uint32) uint16 {
	bucketId := hash % uint32(BUCKETS)
	comparator := nameComparator{buf, nameBuf, hash, r.caseSensitive}
	found := false

	items := r.table[bucketId]

	i := int(len(items))
	for i -= 1; i >= 0; i-- {
		found = comparator.compare(&items[i])
		if found {
			break
		}
	}

	if found {
		return uint16(items[i].pos)
	} else {
		return NO_OFFSET
	}
}

func (r *MsgRender) addOffset(hash, offset, length uint32) {
	index := hash % uint32(BUCKETS)
	r.table[index] = append(r.table[index], offsetItem{hash, uint16(offset), uint16(length)})
}

func (r *MsgRender) Clear() {
	r.buf.Clear()
	r.truncated = false
	r.caseSensitive = false
	for i := uint(0); i < BUCKETS; i++ {
		r.table[i] = r.table[i][:0]
	}
}

func (r *MsgRender) WriteName(name *Name, compress bool) error {
	nlables := name.LabelCount()
	var nlabelsUncomp uint
	ptrOffset := NO_OFFSET

	ref := fromName(name)
	var parentBuf buffer.InputBuffer
	for nlabelsUncomp = 0; nlabelsUncomp < nlables; nlabelsUncomp++ {
		if nlabelsUncomp > 0 {
			ref.Parent()
		}

		if ref.IsRoot() {
			nlabelsUncomp += 1
			break
		}

		r.seqHashs[nlabelsUncomp] = ref.Hash(r.caseSensitive)
		if compress {
			parentBuf.SetData(ref.Raw())
			ptrOffset = r.findOffset(r.buf, &parentBuf, r.seqHashs[nlabelsUncomp])
			if ptrOffset != NO_OFFSET {
				break
			}
		}
	}

	offset := r.buf.Len()
	if compress == false || nlabelsUncomp == nlables {
		if err := r.buf.WriteData(name.raw); err != nil {
			return err
		}
	} else if nlabelsUncomp > 0 {
		compLabelOffset := name.offsets[nlabelsUncomp]
		if err := r.buf.WriteData(name.raw[0:compLabelOffset]); err != nil {
			return err
		}
	}

	if compress && (ptrOffset != NO_OFFSET) {
		ptrOffset |= COMPRESS_POINTER_MARK16
		if err := r.buf.WriteUint16(ptrOffset); err != nil {
			return err
		}
	}

	nameLen := name.length
	for i := uint(0); i < nlabelsUncomp; i++ {
		labelLen, _ := r.buf.At(offset)
		if labelLen == 0 {
			break
		}

		if offset > MAX_COMPRESS_POINTER {
			break
		}

		r.addOffset(r.seqHashs[i], uint32(offset), uint32(nameLen))
		offset += int(labelLen + 1)
		nameLen -= uint(labelLen + 1)
	}
	return nil
}

func (r *MsgRender) Data() []uint8 {
	return r.buf.Data()
}

func (r *MsgRender) Len() int {
	return r.buf.Len()
}

func (r *MsgRender) LeftSpace() int {
	return r.buf.LeftSpace()
}

func (r *MsgRender) Skip(length int) error {
	return r.buf.Skip(length)
}

func (r *MsgRender) Truncate(newLen int) error {
	return r.buf.Truncate(newLen)
}

func (r *MsgRender) WriteUint8(data uint8) error {
	return r.buf.WriteUint8(data)
}

func (r *MsgRender) WriteUint16(data uint16) error {
	return r.buf.WriteUint16(data)
}

func (r *MsgRender) WriteUint16At(pos int, data uint16) error {
	return r.buf.WriteUint16At(pos, data)
}

func (r *MsgRender) WriteUint32(data uint32) error {
	return r.buf.WriteUint32(data)
}

func (r *MsgRender) WriteData(data []uint8) error {
	return r.buf.WriteData(data)
}
