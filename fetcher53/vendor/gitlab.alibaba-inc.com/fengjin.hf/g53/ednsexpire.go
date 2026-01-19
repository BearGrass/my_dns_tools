package g53

import (
	"fmt"

	"gitlab.alibaba-inc.com/fengjin.hf/cement/buffer"
)

const (
	EDNS_EXPIRE = 9
)

type ExpireOption struct {
	Expire *uint32
}

func (o *ExpireOption) Rend(render *MsgRender) {
	render.WriteUint16(EDNS_EXPIRE)
	if o.Expire != nil {
		render.WriteUint16(4)
		render.WriteUint32(*o.Expire)
	} else {
		render.WriteUint16(0)
	}
}

func (o *ExpireOption) String() string {
	if o.Expire != nil {
		return fmt.Sprintf("; EXPIRE %d\n", *o.Expire)
	} else {
		return "; EXPIRE \n"
	}
}

func expireOptFromWire(buf *buffer.InputBuffer) (Option, error) {
	l, err := buf.ReadUint16()
	if err != nil {
		return nil, err
	}

	if l == 0 {
		return &ExpireOption{}, nil
	}

	if l != 4 {
		return nil, fmt.Errorf("expire lenght isn't 4")
	}
	expireTime, err := buf.ReadUint32()
	if err != nil {
		return nil, err
	}
	return &ExpireOption{
		Expire: &expireTime,
	}, nil
}

func expireOptFromRdata(rdata Rdata) Option {
	opt := rdata.(*OPT)
	if len(opt.Data) == 0 {
		return nil
	}

	buf := buffer.NewInputBuffer(opt.Data)
	code, _ := buf.ReadUint16()
	if code != EDNS_EXPIRE {
		return nil
	}

	option, err := expireOptFromWire(buf)
	if err == nil {
		return option
	} else {
		return nil
	}
}

func (e *EDNS) SetExpireTime(expire uint32) error {
	e.Options = append(e.Options, &ExpireOption{
		Expire: &expire,
	})
	return nil
}
