package g53

import (
	"strings"

	"gitlab.alibaba-inc.com/fengjin.hf/cement/buffer"
)

type Question struct {
	Name  Name
	Type  RRType
	Class RRClass
}

func QuestionFromWire(buf *buffer.InputBuffer) (*Question, error) {
	var q Question
	if err := q.FromWire(buf); err != nil {
		return nil, err
	} else {
		return &q, nil
	}
}

func (q *Question) Clone() Question {
	return Question{
		Name:  q.Name.Clone(),
		Type:  q.Type,
		Class: q.Class,
	}
}

func (q *Question) FromWire(buf *buffer.InputBuffer) error {
	if err := q.Name.FromWire(buf, false); err != nil {
		return err
	}

	t, err := TypeFromWire(buf)
	if err != nil {
		return err
	}

	cls, err := ClassFromWire(buf)
	if err != nil {
		return err
	}
	q.Type = t
	q.Class = cls
	return nil
}

func (q *Question) Rend(r *MsgRender) {
	q.Name.Rend(r)
	q.Type.Rend(r)
	q.Class.Rend(r)
}

func (q *Question) ToWire(buf *buffer.OutputBuffer) {
	q.Name.ToWire(buf)
	q.Type.ToWire(buf)
	q.Class.ToWire(buf)
}

func (q *Question) String() string {
	return strings.Join([]string{q.Name.String(false), q.Class.String(), q.Type.String()}, " ")
}

func (q *Question) Equals(o *Question) bool {
	return q.Name.Equals(&o.Name) &&
		q.Type == o.Type &&
		q.Class == o.Class
}
