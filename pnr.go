package main

// Filtru de program (#pnr=N), ca la Astra: dintr-un MPTS păstrează un singur program.
// PID-urile programului rămân cele originale; PAT-ul e regenerat doar cu programul ales.
// Trec mai departe: PMT-ul programului, PID-urile ES, PCR, ECM (descriptori CA din PMT),
// SDT și EIT rescrise doar cu serviciul ales, plus CAT, NIT, TDT/TOT neschimbate.

type pnrFilter struct {
	pnr     int
	pmtPID  int
	keep    map[int]bool
	asm     map[int][]byte
	patCC   byte
	patVer  byte
	sdtCC   byte
	eitCC   byte
	tsid    int
	havePAT bool
}

func newPNRFilter(pnr int) *pnrFilter {
	return &pnrFilter{pnr: pnr, pmtPID: -1, keep: map[int]bool{}, asm: map[int][]byte{}}
}

var crcTable = func() (t [256]uint32) {
	for i := range t {
		c := uint32(i) << 24
		for j := 0; j < 8; j++ {
			if c&0x80000000 != 0 {
				c = c<<1 ^ 0x04C11DB7
			} else {
				c <<= 1
			}
		}
		t[i] = c
	}
	return
}()

func crc32mpeg(b []byte) uint32 {
	c := uint32(0xFFFFFFFF)
	for _, x := range b {
		c = c<<8 ^ crcTable[byte(c>>24)^x]
	}
	return c
}

// feed adaugă payload-ul unui pachet PSI și întoarce secțiunile complete (cu CRC corect)
func (f *pnrFilter) feed(pid int, pusi bool, pl []byte) [][]byte {
	var out [][]byte
	buf := f.asm[pid]
	if pusi {
		ptr := int(pl[0])
		if 1+ptr > len(pl) {
			delete(f.asm, pid)
			return nil
		}
		if buf != nil {
			buf = append(buf, pl[1:1+ptr]...)
			out = append(out, drainSections(&buf)...)
		}
		buf = append([]byte(nil), pl[1+ptr:]...)
	} else {
		if buf == nil {
			return nil
		}
		buf = append(buf, pl...)
	}
	out = append(out, drainSections(&buf)...)
	if len(buf) == 0 || len(buf) > 4096 {
		delete(f.asm, pid)
	} else {
		f.asm[pid] = buf
	}
	return out
}

// drainSections scoate toate secțiunile complete din buffer; restul rămâne pentru pachetul următor
func drainSections(buf *[]byte) [][]byte {
	var out [][]byte
	for {
		b := *buf
		if len(b) == 0 || b[0] == 0xFF {
			*buf = nil
			return out
		}
		if len(b) < 3 {
			return out
		}
		sl := int(b[1]&0x0F)<<8 | int(b[2])
		if len(b) < 3+sl {
			return out
		}
		if sl >= 9 && crc32mpeg(b[:3+sl]) == 0 {
			out = append(out, append([]byte(nil), b[:3+sl]...))
		}
		*buf = b[3+sl:]
	}
}

// packetize pune o secțiune în pachete TS (cu pointer_field și umplutură 0xFF)
func packetize(pid int, sec []byte, cc *byte) []byte {
	var out []byte
	first := true
	for len(sec) > 0 || first {
		p := make([]byte, tsSize)
		p[0], p[1], p[2], p[3] = 0x47, byte(pid>>8)&0x1F, byte(pid), 0x10|*cc
		*cc = (*cc + 1) & 0x0F
		o := 4
		if first {
			p[1] |= 0x40
			p[4] = 0
			o = 5
			first = false
		}
		n := copy(p[o:], sec)
		sec = sec[n:]
		for i := o + n; i < tsSize; i++ {
			p[i] = 0xFF
		}
		out = append(out, p...)
	}
	return out
}

// sdtFor rescrie SDT-ul (tabela 0x42) păstrând doar serviciul ales
func (f *pnrFilter) sdtFor(s []byte) []byte {
	if s[0] != 0x42 || len(s) < 15 {
		return nil
	}
	end := len(s) - 4
	for i := 11; i+5 <= end; {
		dll := int(s[i+3]&0x0F)<<8 | int(s[i+4])
		if i+5+dll > end {
			return nil
		}
		if int(s[i])<<8|int(s[i+1]) == f.pnr {
			n := append(append([]byte(nil), s[:11]...), s[i:i+5+dll]...)
			l := len(n) + 4 - 3
			n[1] = n[1]&0xF0 | byte(l>>8)&0x0F
			n[2] = byte(l)
			n[6], n[7] = 0, 0 // section_number / last_section_number
			c := crc32mpeg(n)
			return append(n, byte(c>>24), byte(c>>16), byte(c>>8), byte(c))
		}
		i += 5 + dll
	}
	return nil
}

func (f *pnrFilter) onPAT(s []byte) {
	if s[0] != 0x00 {
		return
	}
	f.tsid = int(s[3])<<8 | int(s[4])
	f.patVer = (s[5] >> 1) & 0x1F
	f.havePAT = true
	for i := 8; i+4 <= len(s)-4; i += 4 {
		prog := int(s[i])<<8 | int(s[i+1])
		if prog == f.pnr {
			p := int(s[i+2]&0x1F)<<8 | int(s[i+3])
			if p != f.pmtPID {
				f.pmtPID = p
				f.keep = map[int]bool{}
			}
			return
		}
	}
	f.pmtPID = -1
	f.keep = map[int]bool{}
}

func caPIDs(desc []byte, keep map[int]bool) {
	for j := 0; j+2 <= len(desc); {
		tag, l := desc[j], int(desc[j+1])
		if j+2+l > len(desc) {
			return
		}
		if tag == 0x09 && l >= 4 {
			keep[int(desc[j+4]&0x1F)<<8|int(desc[j+5])] = true
		}
		j += 2 + l
	}
}

func (f *pnrFilter) onPMT(s []byte) {
	if s[0] != 0x02 || len(s) < 16 || int(s[3])<<8|int(s[4]) != f.pnr {
		return
	}
	k := map[int]bool{int(s[8]&0x1F)<<8 | int(s[9]): true} // PCR
	pil := int(s[10]&0x0F)<<8 | int(s[11])
	end := len(s) - 4
	if 12+pil <= end {
		caPIDs(s[12:12+pil], k)
	}
	for i := 12 + pil; i+5 <= end; {
		ep := int(s[i+1]&0x1F)<<8 | int(s[i+2])
		el := int(s[i+3]&0x0F)<<8 | int(s[i+4])
		if i+5+el > end {
			break
		}
		k[ep] = true
		caPIDs(s[i+5:i+5+el], k)
		i += 5 + el
	}
	f.keep = k
}

func (f *pnrFilter) patPacket() []byte {
	sec := []byte{0x00, 0xB0, 13, byte(f.tsid >> 8), byte(f.tsid), 0xC1 | f.patVer<<1, 0, 0,
		byte(f.pnr >> 8), byte(f.pnr), 0xE0 | byte(f.pmtPID>>8), byte(f.pmtPID)}
	c := crc32mpeg(sec)
	sec = append(sec, byte(c>>24), byte(c>>16), byte(c>>8), byte(c))
	p := make([]byte, tsSize)
	p[0], p[1], p[2], p[3], p[4] = 0x47, 0x40, 0x00, 0x10|f.patCC, 0x00
	f.patCC = (f.patCC + 1) & 0x0F
	copy(p[5:], sec)
	for i := 5 + len(sec); i < tsSize; i++ {
		p[i] = 0xFF
	}
	return p
}

// Filter primește pachete TS aliniate și întoarce doar ce aparține programului
func (f *pnrFilter) Filter(chunk []byte) []byte {
	out := make([]byte, 0, len(chunk))
	for i := 0; i+tsSize <= len(chunk); i += tsSize {
		p := chunk[i : i+tsSize]
		pid := int(p[1]&0x1F)<<8 | int(p[2])
		pusi := p[1]&0x40 != 0
		afc := (p[3] >> 4) & 3
		off := 4
		if afc&2 != 0 {
			off = 5 + int(p[4])
		}
		hasPL := afc&1 != 0 && off < tsSize
		switch {
		case pid == 0:
			if hasPL {
				for _, s := range f.feed(0, pusi, p[off:]) {
					f.onPAT(s)
				}
			}
			if pusi && f.pmtPID >= 0 {
				out = append(out, f.patPacket()...)
			}
		case pid == f.pmtPID:
			if hasPL {
				for _, s := range f.feed(pid, pusi, p[off:]) {
					f.onPMT(s)
				}
			}
			out = append(out, p...)
		case pid == 0x11: // SDT doar pentru programul ales
			if hasPL {
				for _, s := range f.feed(pid, pusi, p[off:]) {
					if n := f.sdtFor(s); n != nil {
						out = append(out, packetize(0x11, n, &f.sdtCC)...)
					}
				}
			}
		case pid == 0x12: // EIT (EPG) doar pentru programul ales
			if hasPL {
				for _, s := range f.feed(pid, pusi, p[off:]) {
					if (s[0] == 0x4E || (s[0] >= 0x50 && s[0] <= 0x5F)) && int(s[3])<<8|int(s[4]) == f.pnr {
						out = append(out, packetize(0x12, s, &f.eitCC)...)
					}
				}
			}
		case pid == 0x01 || pid == 0x10 || pid == 0x14 || f.keep[pid]:
			out = append(out, p...)
		}
	}
	return out
}
