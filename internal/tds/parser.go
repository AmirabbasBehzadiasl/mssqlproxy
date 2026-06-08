package tds

import (
    "encoding/binary"
    "encoding/hex"
    "unicode/utf16"
)

type Parser struct {
    buf []byte
}

func NewParser() *Parser {
    return &Parser{buf: make([]byte, 0, 4096)}
}

func (p *Parser) Feed(data []byte) []string {
    p.buf = append(p.buf, data...)
    var results []string
    for len(p.buf) >= 8 {
        msgType := p.buf[0]
        length := binary.BigEndian.Uint16(p.buf[2:4])
        if int(length) < 8 || int(length) > len(p.buf) {
            break
        }
        payload := p.buf[8:length]
        switch msgType {
        case 0x01: // SQL Batch
            if len(payload) > 0 {
                sql := utf16BytesToString(payload)
                results = append(results, sql)
            }
        case 0x03: // RPC Request
            if len(payload) > 4 {
                dumpLen := min(64, len(payload))
                results = append(results, "[RPC] "+hex.EncodeToString(payload[:dumpLen]))
            }
        }
        p.buf = p.buf[length:]
    }
    return results
}

// ParsePreLogin reads a Pre-Login message and returns the encryption byte.
func ParsePreLogin(data []byte) (encrypt byte, found bool) {
    if len(data) < 8 || data[0] != 0x12 && data[0] != 0x04 { // Pre-Login request (0x12) or response (0x04)
        return 0, false
    }
    msgLen := binary.BigEndian.Uint16(data[2:4])
    if int(msgLen) > len(data) {
        return 0, false
    }
    // Option stream starts after 8-byte header
    pos := 8
    for pos+5 <= int(msgLen) {
        tokenType := data[pos]
        offset := binary.BigEndian.Uint16(data[pos+1 : pos+3])
        length := binary.BigEndian.Uint16(data[pos+3 : pos+5])
        pos += 5

        if tokenType == 0x01 { // ENCRYPTION
            if int(offset)+int(length) <= int(msgLen) && length >= 1 {
                encrypt = data[offset] // offset is absolute from start of message
                found = true
                return
            }
        }
        if tokenType == 0xFF { // Terminator token
            break
        }
    }
    return 0, false
}

func utf16BytesToString(b []byte) string {
    if len(b)%2 != 0 {
        return string(b)
    }
    u16 := make([]uint16, len(b)/2)
    for i := range u16 {
        u16[i] = binary.LittleEndian.Uint16(b[i*2 : i*2+2])
    }
    return string(utf16.Decode(u16))
}

func min(a, b int) int {
    if a < b { return a }
    return b
}