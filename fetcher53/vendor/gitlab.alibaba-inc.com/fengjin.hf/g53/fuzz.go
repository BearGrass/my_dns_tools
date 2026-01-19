package g53

import (
	"gitlab.alibaba-inc.com/fengjin.hf/cement/buffer"
)

func Fuzz(data []byte) int {
	buf := buffer.NewInputBuffer(data)
	msg, err := MessageFromWire(buf)
	if err != nil {
		return 0
	}

	render := NewMsgRender(512)
	msg.Rend(render)
	return 1
}
