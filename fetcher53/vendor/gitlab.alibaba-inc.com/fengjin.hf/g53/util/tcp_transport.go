package util

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"time"
)

const tcpTimeout = 5 * time.Second

var ErrTCPDataExceedBufferLen = errors.New("tcp data exceed buffer len")

func NewTCPConn(address string) (*net.TCPConn, error) {
	conn, err := net.DialTimeout("tcp", address, tcpTimeout)
	if err != nil {
		return nil, err
	}

	return conn.(*net.TCPConn), nil
}

func TCPWrite(data []byte, conn *net.TCPConn) error {
	size := uint16(len(data))
	if err := binary.Write(conn, binary.BigEndian, &size); err != nil {
		return err
	}

	conn.SetWriteDeadline(time.Now().Add(tcpTimeout))
	_, err := conn.Write(data)
	return err
}

func TCPRead(conn *net.TCPConn, buf []byte) (int, error) {
	var msgSize uint16
	conn.SetReadDeadline(time.Now().Add(tcpTimeout))
	if err := binary.Read(conn, binary.BigEndian, &msgSize); err != nil {
		return 0, err
	}

	if int(msgSize) > len(buf) {
		return 0, ErrTCPDataExceedBufferLen
	}

	conn.SetReadDeadline(time.Now().Add(tcpTimeout))
	if _, err := io.ReadFull(conn, buf[:msgSize]); err == nil {
		return int(msgSize), nil
	} else {
		return 0, err
	}
}
