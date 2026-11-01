package yamora

import (
	"encoding/binary"
	"io"
	"net"
)

type binaryWire struct {
	conn     net.Conn
	cap      int
	controls int
	goaway   bool
}
type binaryFrame struct {
	kind    byte
	stream  uint32
	payload []byte
}

func (w *binaryWire) send(kind byte, stream uint32, payload []byte) error {
	var h [16]byte
	copy(h[:4], "YMBF")
	h[4], h[5] = 1, kind
	binary.BigEndian.PutUint32(h[8:12], stream)
	binary.BigEndian.PutUint32(h[12:], uint32(len(payload)))
	for _, part := range [][]byte{h[:], payload} {
		for len(part) != 0 {
			n, err := w.conn.Write(part)
			if err != nil || n <= 0 {
				return errBinaryTransport
			}
			part = part[n:]
		}
	}
	return nil
}
func (w *binaryWire) receive() (binaryFrame, error) {
	var h [16]byte
	if _, err := io.ReadFull(w.conn, h[:]); err != nil {
		return binaryFrame{}, errBinaryTransport
	}
	f := binaryFrame{kind: h[5], stream: binary.BigEndian.Uint32(h[8:12])}
	n := binary.BigEndian.Uint32(h[12:])
	if string(h[:4]) != "YMBF" || h[4] != 1 || h[6] != 0 || h[7] != 0 || n > uint32(w.cap) {
		return f, errBinaryProtocol
	}
	// Validate shape and method-independent ceilings before allocating peer data.
	switch f.kind {
	case 1:
		if f.stream != 0 || n != 12 {
			return f, errBinaryProtocol
		}
	case 3:
		if f.stream != 1 || n == 0 || n > 2048 {
			return f, errBinaryProtocol
		}
	case 4:
		if f.stream != 1 || n == 0 {
			return f, errBinaryProtocol
		}
	case 5:
		if f.stream != 1 || n != 0 {
			return f, errBinaryProtocol
		}
	case 7:
		if f.stream != 1 || n != 4 {
			return f, errBinaryProtocol
		}
	case 8, 9:
		if f.stream != 0 || n != 8 {
			return f, errBinaryProtocol
		}
	case 10:
		if f.stream != 0 || n != 0 {
			return f, errBinaryProtocol
		}
	default:
		return f, errBinaryProtocol
	}
	f.payload = make([]byte, int(n))
	if _, err := io.ReadFull(w.conn, f.payload); err != nil {
		return f, errBinaryTransport
	}
	return f, nil
}
func (w *binaryWire) hello() error { return w.helloProtocol(1) }
func (w *binaryWire) helloProtocol(protocol uint16) error {
	var h [12]byte
	binary.BigEndian.PutUint16(h[:2], 1)
	binary.BigEndian.PutUint16(h[2:4], protocol)
	binary.BigEndian.PutUint32(h[4:8], uint32(w.cap))
	binary.BigEndian.PutUint32(h[8:], 1)
	if err := w.send(1, 0, h[:]); err != nil {
		return err
	}
	f, err := w.receive()
	if err != nil {
		return err
	}
	if f.kind != 1 {
		return errBinaryProtocol
	}
	minimum, maximum := binary.BigEndian.Uint16(f.payload[:2]), binary.BigEndian.Uint16(f.payload[2:4])
	frames, streams := binary.BigEndian.Uint32(f.payload[4:8]), binary.BigEndian.Uint32(f.payload[8:])
	if minimum < 1 || minimum > protocol || maximum < minimum || frames < 4096 || frames > 1048576 || streams < 1 || streams > 128 {
		return errBinaryProtocol
	}
	if protocol == 2 && maximum < 2 {
		return ErrBinaryUnsupported
	}
	w.cap = min(w.cap, int(frames))
	return nil
}
func (w *binaryWire) control(f binaryFrame) (bool, error) {
	if f.kind != 8 && f.kind != 10 {
		return false, nil
	}
	w.controls++
	if w.controls > 16 {
		return true, errBinaryProtocol
	}
	if f.kind == 8 {
		return true, w.send(9, 0, f.payload)
	}
	if w.goaway {
		return true, errBinaryProtocol
	}
	w.goaway = true // No accepted-ID watermark or replay guarantee.
	return true, nil
}
func binaryTLV(out []byte, id uint16, value []byte) []byte {
	out = binary.BigEndian.AppendUint16(out, id)
	out = binary.BigEndian.AppendUint16(out, uint16(len(value)))
	return append(out, value...)
}
func binaryRequest(method byte, path string, source []byte, token, match, none, id string, timeout int) []byte {
	out := []byte{0, 1, 0, 0}
	count := uint16(4)
	out = binaryTLV(out, 1, []byte{method})
	out = binaryTLV(out, 2, []byte(path))
	media := ""
	if method == 3 {
		media = "application/yaml"
	}
	out = binaryTLV(out, 3, []byte(media))
	out = binaryTLV(out, 4, binary.BigEndian.AppendUint64(nil, uint64(len(source))))
	for i, text := range []string{token, match, none} {
		if text != "" {
			if i == 0 {
				text = "Bearer " + text
			}
			out = binaryTLV(out, uint16(5+i), []byte(text))
			count++
		}
	}
	if id != "" {
		out = binaryTLV(out, 8, binaryIDBytes(id))
		count++
	}
	out = binaryTLV(out, 9, binary.BigEndian.AppendUint32(nil, uint32(timeout)))
	count++
	binary.BigEndian.PutUint16(out[2:4], count)
	return out
}
