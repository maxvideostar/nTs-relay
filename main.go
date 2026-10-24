// StreamHub — server de redistribuire MPEG-TS (stil Astra) cu păstrarea PID-urilor originale.
// Intrări: udp:// rtp:// (multicast/unicast), http(s):// (TS sau HLS .m3u8), srt://, rtmp://, rtmp-listen://
// Ieșiri:  HTTP-TS /play/{id}, HLS /hls/{id}/index.m3u8, UDP/multicast
package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"
)

const (
	version = "1.5.0"
	tsSize  = 188
	ua      = "StreamHub/" + version
)

var startTime = time.Now()

// ============================== CONFIG ==============================

type ChannelConfig struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Enabled bool     `json:"enabled"`
	Inputs  []string `json:"inputs"`
	HTTP    bool     `json:"http"`
	HLS     bool     `json:"hls"`
	UDP     string   `json:"udp"`
	Public  bool     `json:"public"`
}

type Config struct {
	Listen      string           `json:"listen"`
	ListenExtra []string         `json:"listen_extra,omitempty"` // porturi suplimentare, ex. [":7000"]
	AdminUser   string           `json:"admin_user"`
	AdminPass   string           `json:"admin_pass"`
	Tokens      []string         `json:"tokens"`
	HLSSegment  int              `json:"hls_segment"`
	HLSWindow   int              `json:"hls_window"`
	Channels    []*ChannelConfig `json:"channels"`
}

func randHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// ============================== TS ALIGNER ==============================

// Aligner primește bytes arbitrari și emite doar pachete TS întregi, aliniate pe 0x47.
type Aligner struct {
	buf    []byte
	synced bool
}

func (a *Aligner) Push(d []byte, out func([]byte)) {
	a.buf = append(a.buf, d...)
	b := a.buf
	i := 0
	res := make([]byte, 0, len(b))
	for len(b)-i >= tsSize {
		if a.synced {
			if b[i] == 0x47 {
				res = append(res, b[i:i+tsSize]...)
				i += tsSize
				continue
			}
			a.synced = false
		}
		if len(b)-i < 2*tsSize+1 {
			break
		}
		if b[i] == 0x47 && b[i+tsSize] == 0x47 && b[i+2*tsSize] == 0x47 {
			a.synced = true
			continue
		}
		i++
	}
	a.buf = append(a.buf[:0], b[i:]...)
	if len(res) > 0 {
		out(res)
	}
}

// ============================== ANALYZER ==============================

type PIDInfo struct {
	PID        int    `json:"pid"`
	Type       string `json:"type"`
	Kind       string `json:"kind"`
	Lang       string `json:"lang,omitempty"`
	Kbps       int    `json:"kbps"`
	CC         uint64 `json:"cc"`
	Scrambled  bool   `json:"scrambled"`
	StreamType int    `json:"-"`
	lastCC     int
	win        uint64
	scr        int
	idle       int
}

type pktInfo struct {
	start  bool // început PES pe stream-ul principal (video sau audio dacă nu e video)
	key    bool
	pts    int64
	hasPTS bool
}

type Analyzer struct {
	mu        sync.Mutex
	pids      map[int]*PIDInfo
	pmtPIDs   map[int]bool
	psiBuf    map[int][]byte
	psiPkts   map[int][][]byte
	videoPID  int
	videoType int
	audioPID  int
	service   string
	provider  string
	cc        uint64
	win       uint64
	kbps      int
	last      time.Time
}

func NewAnalyzer() *Analyzer {
	a := &Analyzer{last: time.Now()}
	a.reset()
	return a
}

func (a *Analyzer) reset() {
	a.pids = map[int]*PIDInfo{}
	a.pmtPIDs = map[int]bool{}
	a.psiBuf = map[int][]byte{}
	a.psiPkts = map[int][][]byte{}
	a.videoPID, a.videoType, a.audioPID = 0, 0, 0
	a.service, a.provider = "", ""
}

// Reset la schimbarea sursei: nu numără erori CC false.
func (a *Analyzer) Reset() {
	a.mu.Lock()
	a.reset()
	a.mu.Unlock()
}

func fixedPIDType(pid int) (string, string) {
	switch pid {
	case 0x00:
		return "PAT", "psi"
	case 0x01:
		return "CAT", "psi"
	case 0x10:
		return "NIT", "psi"
	case 0x11:
		return "SDT", "psi"
	case 0x12:
		return "EIT", "psi"
	case 0x14:
		return "TDT/TOT", "psi"
	case 0x1FFF:
		return "Null", "null"
	}
	return "Necunoscut", "data"
}

func (a *Analyzer) getPID(pid int) *PIDInfo {
	pi := a.pids[pid]
	if pi == nil {
		pi = &PIDInfo{PID: pid, lastCC: -1}
		pi.Type, pi.Kind = fixedPIDType(pid)
		if a.pmtPIDs[pid] {
			pi.Type, pi.Kind = "PMT", "psi"
		}
		a.pids[pid] = pi
	}
	return pi
}

func (a *Analyzer) Process(p []byte) pktInfo {
	var inf pktInfo
	pid := int(p[1]&0x1F)<<8 | int(p[2])
	pusi := p[1]&0x40 != 0
	afc := (p[3] >> 4) & 3
	cc := int(p[3] & 0x0F)
	off := 4
	disc, rai := false, false
	if afc&2 != 0 {
		al := int(p[4])
		if al > 0 && al <= 183 {
			disc = p[5]&0x80 != 0
			rai = p[5]&0x40 != 0
		}
		off = 5 + al
	}
	hasPL := afc&1 != 0 && off < tsSize

	a.mu.Lock()
	defer a.mu.Unlock()
	pi := a.getPID(pid)
	pi.win += tsSize
	a.win += tsSize
	if p[3]&0xC0 != 0 {
		pi.scr++
	}
	if pid != 0x1FFF && hasPL {
		if pi.lastCC >= 0 && !disc {
			if exp := (pi.lastCC + 1) & 0xF; cc != exp && cc != pi.lastCC {
				pi.CC++
				a.cc++
			}
		}
		pi.lastCC = cc
	}
	if !hasPL {
		return inf
	}
	pl := p[off:]
	if pid == 0 || pid == 0x11 || a.pmtPIDs[pid] {
		if pid != 0x11 {
			if pusi {
				a.psiPkts[pid] = [][]byte{append([]byte(nil), p...)}
			} else if n := len(a.psiPkts[pid]); n > 0 && n < 8 {
				a.psiPkts[pid] = append(a.psiPkts[pid], append([]byte(nil), p...))
			}
		}
		a.psi(pid, pusi, pl)
		return inf
	}
	if pusi && len(pl) >= 9 && pl[0] == 0 && pl[1] == 0 && pl[2] == 1 {
		lead := a.videoPID
		if lead == 0 {
			lead = a.audioPID
		}
		if lead != 0 && pid == lead {
			inf.start = true
			if pl[7]&0x80 != 0 && len(pl) >= 14 {
				inf.pts = parsePTS(pl[9:14])
				inf.hasPTS = true
			}
			if pid == a.videoPID {
				inf.key = rai
				if hl := 9 + int(pl[8]); !inf.key && hl < len(pl) {
					inf.key = scanKey(pl[hl:], a.videoType)
				}
			} else {
				inf.key = true
			}
		}
	}
	return inf
}

func parsePTS(b []byte) int64 {
	return int64(b[0]>>1&7)<<30 | int64(b[1])<<22 | int64(b[2]>>1)<<15 | int64(b[3])<<7 | int64(b[4]>>1)
}

func scanKey(es []byte, st int) bool {
	for i := 0; i+3 < len(es); i++ {
		if es[i] != 0 || es[i+1] != 0 || es[i+2] != 1 {
			continue
		}
		n := es[i+3]
		switch st {
		case 0x1B: // H.264
			if t := n & 0x1F; t == 5 || t == 7 {
				return true
			}
		case 0x24: // HEVC
			if t := (n >> 1) & 0x3F; (t >= 16 && t <= 21) || t == 32 || t == 33 {
				return true
			}
		case 0x01, 0x02: // MPEG-2
			if n == 0xB3 {
				return true
			}
		case 0x10: // MPEG-4 part 2
			if n == 0xB0 || n == 0xB3 {
				return true
			}
		}
	}
	return false
}

func (a *Analyzer) psi(pid int, pusi bool, pl []byte) {
	buf := a.psiBuf[pid]
	if pusi {
		ptr := int(pl[0])
		if 1+ptr > len(pl) {
			delete(a.psiBuf, pid)
			return
		}
		if buf != nil && ptr > 0 {
			a.trySection(pid, append(buf, pl[1:1+ptr]...))
		}
		buf = append([]byte(nil), pl[1+ptr:]...)
	} else {
		if buf == nil {
			return
		}
		buf = append(buf, pl...)
	}
	if a.trySection(pid, buf) || len(buf) > 4096 {
		delete(a.psiBuf, pid)
		return
	}
	a.psiBuf[pid] = buf
}

func (a *Analyzer) trySection(pid int, b []byte) bool {
	if len(b) < 3 {
		return false
	}
	if b[0] == 0xFF {
		return true
	}
	sl := int(b[1]&0x0F)<<8 | int(b[2])
	if len(b) < 3+sl {
		return false
	}
	s := b[:3+sl]
	switch {
	case pid == 0 && s[0] == 0x00:
		a.parsePAT(s)
	case pid == 0x11 && s[0] == 0x42:
		a.parseSDT(s)
	case s[0] == 0x02:
		a.parsePMT(s)
	}
	return true
}

func (a *Analyzer) parsePAT(s []byte) {
	if len(s) < 12 {
		return
	}
	end := len(s) - 4
	m := map[int]bool{}
	for i := 8; i+4 <= end; i += 4 {
		prog := int(s[i])<<8 | int(s[i+1])
		p := int(s[i+2]&0x1F)<<8 | int(s[i+3])
		if prog != 0 {
			m[p] = true
		}
	}
	for p := range a.pmtPIDs {
		if !m[p] {
			delete(a.psiPkts, p)
		}
	}
	a.pmtPIDs = m
	for p := range m {
		pi := a.getPID(p)
		pi.Type, pi.Kind = "PMT", "psi"
	}
}

func (a *Analyzer) parsePMT(s []byte) {
	if len(s) < 16 {
		return
	}
	pil := int(s[10]&0x0F)<<8 | int(s[11])
	i, end := 12+pil, len(s)-4
	video, vtype, audio := 0, 0, 0
	for i+5 <= end {
		st := int(s[i])
		ep := int(s[i+1]&0x1F)<<8 | int(s[i+2])
		el := int(s[i+3]&0x0F)<<8 | int(s[i+4])
		if i+5+el > end {
			break
		}
		typ, kind, lang := streamTypeName(st, s[i+5:i+5+el])
		pi := a.getPID(ep)
		pi.Type, pi.Kind, pi.Lang, pi.StreamType = typ, kind, lang, st
		if kind == "video" && video == 0 {
			video, vtype = ep, st
		}
		if kind == "audio" && audio == 0 {
			audio = ep
		}
		i += 5 + el
	}
	a.videoPID, a.videoType, a.audioPID = video, vtype, audio
}

func streamTypeName(st int, desc []byte) (string, string, string) {
	lang, reg := "", ""
	has := map[byte]bool{}
	for j := 0; j+2 <= len(desc); {
		tag, l := desc[j], int(desc[j+1])
		if j+2+l > len(desc) {
			break
		}
		d := desc[j+2 : j+2+l]
		has[tag] = true
		if tag == 0x0A && l >= 3 {
			lang = cleanStr(d[:3])
		}
		if tag == 0x05 && l >= 4 {
			reg = string(d[:4])
		}
		if (tag == 0x56 || tag == 0x59) && l >= 3 && lang == "" {
			lang = cleanStr(d[:3])
		}
		j += 2 + l
	}
	switch st {
	case 0x01:
		return "MPEG-1 Video", "video", lang
	case 0x02:
		return "MPEG-2 Video", "video", lang
	case 0x10:
		return "MPEG-4 Video", "video", lang
	case 0x1B:
		return "H.264", "video", lang
	case 0x24:
		return "HEVC", "video", lang
	case 0x03:
		return "MPEG-1 Audio", "audio", lang
	case 0x04:
		return "MPEG-2 Audio", "audio", lang
	case 0x0F:
		return "AAC", "audio", lang
	case 0x11:
		return "AAC-LATM", "audio", lang
	case 0x81:
		return "AC-3", "audio", lang
	case 0x87:
		return "E-AC-3", "audio", lang
	case 0x86:
		return "SCTE-35", "data", lang
	case 0x15:
		return "ID3", "data", lang
	case 0x06:
		switch {
		case has[0x6A] || reg == "AC-3":
			return "AC-3", "audio", lang
		case has[0x7A] || reg == "EAC3":
			return "E-AC-3", "audio", lang
		case has[0x7C]:
			return "AAC", "audio", lang
		case reg == "Opus":
			return "Opus", "audio", lang
		case has[0x56]:
			return "Teletext", "teletext", lang
		case has[0x59]:
			return "DVB Subtitle", "subtitle", lang
		}
		return "Private data", "data", lang
	}
	return fmt.Sprintf("Tip 0x%02X", st), "data", lang
}

func cleanStr(b []byte) string {
	var sb strings.Builder
	for _, c := range b {
		if c >= 0x20 && c < 0x7F {
			sb.WriteByte(c)
		}
	}
	return sb.String()
}

func dvbStr(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	if b[0] < 0x20 {
		cs := b[0]
		b = b[1:]
		if cs == 0x15 && utf8.Valid(b) {
			return strings.TrimSpace(string(b))
		}
		if cs == 0x10 && len(b) >= 2 {
			b = b[2:]
		}
	}
	var sb strings.Builder
	for _, c := range b {
		if c >= 0x20 && (c < 0x80 || c >= 0xA0) {
			sb.WriteRune(rune(c))
		}
	}
	return strings.TrimSpace(sb.String())
}

func (a *Analyzer) parseSDT(s []byte) {
	if len(s) < 15 {
		return
	}
	end := len(s) - 4
	for i := 11; i+5 <= end; {
		dll := int(s[i+3]&0x0F)<<8 | int(s[i+4])
		j, dend := i+5, i+5+dll
		if dend > end {
			return
		}
		for j+2 <= dend {
			tag, l := s[j], int(s[j+1])
			if j+2+l > dend {
				break
			}
			if tag == 0x48 && l >= 3 {
				d := s[j+2 : j+2+l]
				pl := int(d[1])
				if 2+pl < len(d) {
					nl := int(d[2+pl])
					if 3+pl+nl <= len(d) {
						a.provider = dvbStr(d[2 : 2+pl])
						a.service = dvbStr(d[3+pl : 3+pl+nl])
						return
					}
				}
			}
			j += 2 + l
		}
		i = dend
	}
}

// PSIPackets: ultimele pachete PAT + PMT originale (cu PID-urile și CC-urile lor) pentru începutul segmentelor HLS
func (a *Analyzer) PSIPackets() []byte {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []byte
	for _, p := range a.psiPkts[0] {
		out = append(out, p...)
	}
	keys := make([]int, 0, len(a.pmtPIDs))
	for k := range a.pmtPIDs {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	for _, k := range keys {
		for _, p := range a.psiPkts[k] {
			out = append(out, p...)
		}
	}
	return out
}

func (a *Analyzer) Tick() {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now()
	el := now.Sub(a.last).Seconds()
	if el <= 0 {
		el = 1
	}
	a.last = now
	a.kbps = int(float64(a.win) * 8 / el / 1000)
	a.win = 0
	for pid, pi := range a.pids {
		pi.Kbps = int(float64(pi.win) * 8 / el / 1000)
		if pi.win == 0 {
			pi.idle++
		} else {
			pi.idle = 0
		}
		pi.win = 0
		pi.Scrambled = pi.scr > 0
		pi.scr = 0
		if pi.idle > 30 {
			delete(a.pids, pid)
		}
	}
}

type AnalyzerSnap struct {
	Kbps      int
	CC        uint64
	Scrambled bool
	Service   string
	Provider  string
	PIDs      []PIDInfo
}

func (a *Analyzer) Snapshot() AnalyzerSnap {
	a.mu.Lock()
	defer a.mu.Unlock()
	s := AnalyzerSnap{Kbps: a.kbps, CC: a.cc, Service: a.service, Provider: a.provider}
	for _, pi := range a.pids {
		s.PIDs = append(s.PIDs, *pi)
		if pi.Scrambled && (pi.Kind == "video" || pi.Kind == "audio") {
			s.Scrambled = true
		}
	}
	sort.Slice(s.PIDs, func(i, j int) bool { return s.PIDs[i].PID < s.PIDs[j].PID })
	return s
}

// ============================== HLS SEGMENTER ==============================

type Segment struct {
	Seq  int
	Dur  float64
	Data []byte
	Disc bool
}

type HLSSeg struct {
	mu          sync.RWMutex
	segs        []*Segment
	cur         []byte
	curDisc     bool
	started     bool
	startPTS    int64
	hasStartPTS bool
	startWall   time.Time
	seq         int
	discSeq     int
	pendingDisc bool
	target      float64
	window      int
}

func NewHLS(target, window int) *HLSSeg {
	if target < 1 {
		target = 4
	}
	if window < 2 {
		window = 6
	}
	return &HLSSeg{target: float64(target), window: window}
}

func (h *HLSSeg) elapsed(inf pktInfo, now time.Time) float64 {
	if inf.hasPTS && h.hasStartPTS {
		d := float64((inf.pts-h.startPTS)&(1<<33-1)) / 90000
		if d > 0 && d < 60 {
			return d
		}
	}
	return now.Sub(h.startWall).Seconds()
}

func (h *HLSSeg) begin(inf pktInfo, now time.Time, an *Analyzer) {
	h.cur = make([]byte, 0, 1<<20)
	h.cur = append(h.cur, an.PSIPackets()...)
	h.started = true
	h.startPTS, h.hasStartPTS = inf.pts, inf.hasPTS
	h.startWall = now
	h.curDisc = h.pendingDisc
	h.pendingDisc = false
}

func (h *HLSSeg) finish(dur float64) {
	if len(h.cur) == 0 {
		return
	}
	h.segs = append(h.segs, &Segment{Seq: h.seq, Dur: dur, Data: h.cur, Disc: h.curDisc})
	h.seq++
	for len(h.segs) > h.window+4 {
		if h.segs[0].Disc {
			h.discSeq++
		}
		h.segs = h.segs[1:]
	}
	h.cur = nil
}

func (h *HLSSeg) Write(p []byte, inf pktInfo, an *Analyzer) {
	h.mu.Lock()
	defer h.mu.Unlock()
	now := time.Now()
	if inf.start {
		if !h.started {
			if inf.key {
				h.begin(inf, now, an)
			}
		} else if el := h.elapsed(inf, now); (inf.key && el >= h.target) || el >= 3*h.target {
			h.finish(el)
			h.begin(inf, now, an)
		}
	} else if h.started && now.Sub(h.startWall).Seconds() >= 4*h.target {
		// fără stream principal detectat: tăiere pe timp
		h.finish(now.Sub(h.startWall).Seconds())
		h.begin(pktInfo{}, now, an)
	}
	if h.started {
		h.cur = append(h.cur, p...)
	}
}

func (h *HLSSeg) Discontinuity() {
	h.mu.Lock()
	h.started = false
	h.cur = nil
	if h.seq > 0 {
		h.pendingDisc = true
	}
	h.mu.Unlock()
}

func (h *HLSSeg) Playlist(prefix, q string) ([]byte, bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	n := len(h.segs)
	if n == 0 {
		return nil, false
	}
	start := n - h.window
	if start < 0 {
		start = 0
	}
	ds := h.discSeq
	for _, s := range h.segs[:start] {
		if s.Disc {
			ds++
		}
	}
	segs := h.segs[start:]
	td := int(h.target)
	for _, s := range segs {
		if c := int(math.Ceil(s.Dur)); c > td {
			td = c
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "#EXTM3U\n#EXT-X-VERSION:3\n#EXT-X-TARGETDURATION:%d\n#EXT-X-MEDIA-SEQUENCE:%d\n#EXT-X-DISCONTINUITY-SEQUENCE:%d\n", td, segs[0].Seq, ds)
	for _, s := range segs {
		if s.Disc {
			b.WriteString("#EXT-X-DISCONTINUITY\n")
		}
		fmt.Fprintf(&b, "#EXTINF:%.3f,\n%s%d.ts%s\n", s.Dur, prefix, s.Seq, q)
	}
	return []byte(b.String()), true
}

func (h *HLSSeg) Get(seq int) []byte {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for _, s := range h.segs {
		if s.Seq == seq {
			return s.Data
		}
	}
	return nil
}

func (h *HLSSeg) Count() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.segs)
}

// ============================== UDP OUTPUT ==============================

type UDPOut struct {
	conn  *net.UDPConn
	dst   *net.UDPAddr
	buf   []byte
	errs  atomic.Uint64
	count *atomic.Uint64
}

// udp://[iface@]239.1.1.1:1234?ttl=8
func NewUDPOut(s string) (*UDPOut, error) {
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "udp" && u.Scheme != "rtp") {
		return nil, fmt.Errorf("ieșire UDP invalidă: %s", s)
	}
	iface := ""
	if u.User != nil {
		iface = u.User.Username()
	}
	ttl := 32
	if t, e := strconv.Atoi(u.Query().Get("ttl")); e == nil && t > 0 {
		ttl = t
	}
	dst, err := net.ResolveUDPAddr("udp4", u.Host)
	if err != nil {
		return nil, err
	}
	var ifIP [4]byte
	if iface != "" {
		ifi, err := net.InterfaceByName(iface)
		if err != nil {
			return nil, fmt.Errorf("interfața %s: %v", iface, err)
		}
		addrs, _ := ifi.Addrs()
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil {
				copy(ifIP[:], ipn.IP.To4())
				break
			}
		}
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{})
	if err != nil {
		return nil, err
	}
	rc, _ := conn.SyscallConn()
	rc.Control(func(fd uintptr) { setUDPSockOpts(fd, ttl, iface != "", ifIP) })
	return &UDPOut{conn: conn, dst: dst, buf: make([]byte, 0, 7*tsSize)}, nil
}

func (o *UDPOut) WritePkt(p []byte) {
	o.buf = append(o.buf, p...)
	if len(o.buf) >= 7*tsSize {
		if n, err := o.conn.WriteToUDP(o.buf, o.dst); err != nil {
			o.errs.Add(1)
		} else if o.count != nil {
			o.count.Add(uint64(n))
		}
		o.buf = o.buf[:0]
	}
}

func (o *UDPOut) Close() { o.conn.Close() }

// ============================== INPUTS ==============================

var httpClient = &http.Client{Transport: &http.Transport{
	Proxy:                 http.ProxyFromEnvironment,
	MaxIdleConnsPerHost:   8,
	ResponseHeaderTimeout: 15 * time.Second,
	IdleConnTimeout:       60 * time.Second,
}}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

func readStream(ctx context.Context, r io.Reader, out func([]byte)) error {
	al := &Aligner{}
	buf := make([]byte, 64*1024)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			al.Push(buf[:n], out)
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil {
			if err == io.EOF {
				return errors.New("sursa a închis conexiunea")
			}
			return err
		}
	}
}

func stripRTP(d []byte) []byte {
	if len(d) > 12 && d[0] != 0x47 && d[0]>>6 == 2 {
		h := 12 + 4*int(d[0]&0x0F)
		if d[0]&0x10 != 0 && len(d) > h+4 {
			h += 4 + 4*(int(d[h+2])<<8|int(d[h+3]))
		}
		end := len(d)
		if d[0]&0x20 != 0 {
			end -= int(d[len(d)-1])
		}
		if h < end {
			return d[h:end]
		}
		return nil
	}
	return d
}

func readUDP(ctx context.Context, u *url.URL, out func([]byte)) error {
	iface := ""
	if u.User != nil {
		iface = u.User.Username()
	}
	addr, err := net.ResolveUDPAddr("udp4", u.Host)
	if err != nil {
		return err
	}
	var conn *net.UDPConn
	if addr.IP != nil && addr.IP.IsMulticast() {
		var ifi *net.Interface
		if iface != "" {
			if ifi, err = net.InterfaceByName(iface); err != nil {
				return fmt.Errorf("interfața %s: %v", iface, err)
			}
		}
		conn, err = net.ListenMulticastUDP("udp4", ifi, addr)
	} else {
		conn, err = net.ListenUDP("udp4", addr)
	}
	if err != nil {
		return err
	}
	conn.SetReadBuffer(16 << 20)
	go func() { <-ctx.Done(); conn.Close() }()
	defer conn.Close()
	al := &Aligner{}
	buf := make([]byte, 65536)
	for {
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		if d := stripRTP(buf[:n]); len(d) > 0 {
			al.Push(d, out)
		}
	}
}

func readHTTP(ctx context.Context, src string, out func([]byte)) error {
	if u, _ := url.Parse(src); u != nil && strings.HasSuffix(strings.ToLower(u.Path), ".m3u8") {
		return readHLSAny(ctx, src, out)
	}
	req, err := http.NewRequestWithContext(ctx, "GET", src, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", ua)
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	if ct := strings.ToLower(resp.Header.Get("Content-Type")); strings.Contains(ct, "mpegurl") {
		resp.Body.Close()
		return readHLSAny(ctx, resp.Request.URL.String(), out)
	}
	return readStream(ctx, resp.Body, out)
}

func httpGet(ctx context.Context, u string, timeout time.Duration) ([]byte, string, error) {
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, "GET", u, nil)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("User-Agent", ua)
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, "", fmt.Errorf("HTTP %d la %s", resp.StatusCode, u)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 128<<20))
	return b, resp.Request.URL.String(), err
}

func resolveURL(base, ref string) string {
	b, err := url.Parse(base)
	if err != nil {
		return ref
	}
	r, err := url.Parse(strings.TrimSpace(ref))
	if err != nil {
		return ref
	}
	return b.ResolveReference(r).String()
}

var attrRe = regexp.MustCompile(`([A-Z0-9-]+)=("[^"]*"|[^,]*)`)

func parseAttrs(s string) map[string]string {
	m := map[string]string{}
	for _, x := range attrRe.FindAllStringSubmatch(s, -1) {
		m[x[1]] = strings.Trim(x[2], `"`)
	}
	return m
}

type hlsSegRef struct {
	uri    string
	seq    int
	dur    float64
	keyURI string
	iv     []byte
	method string
}

var errHLSfMP4 = errors.New("HLS cu segmente fMP4")

// readHLSAny: HLS cu segmente .ts → citire nativă (PID-uri originale).
// HLS fMP4/CMAF (fără PID-uri) → ffmpeg remux în TS fără recodare, cu PID-uri fixe.
// Se dă la ffmpeg URL-ul original (master), ca să ia cea mai bună calitate video
// plus pista audio separată, dacă există.
func readHLSAny(ctx context.Context, src string, out func([]byte)) error {
	err := readHLS(ctx, src, out)
	if !errors.Is(err, errHLSfMP4) {
		return err
	}
	return readExec(ctx, "ffmpeg", []string{"-hide_banner", "-loglevel", "error",
		"-user_agent", ua, "-rw_timeout", "15000000",
		"-re", // ritm constant în timp real (altfel ar trimite rafale de câte un segment)
		"-i", src,
		"-c", "copy", "-f", "mpegts", "-mpegts_pmt_start_pid", "0x1000", "-mpegts_start_pid", "0x100",
		"-mpegts_flags", "+resend_headers", "pipe:1"}, out)
}

func readHLS(ctx context.Context, src string, out func([]byte)) error {
	al := &Aligner{}
	plURL := src
	lastSeq := -1
	keys := map[string][]byte{}
	for {
		body, finalURL, err := httpGet(ctx, plURL, 15*time.Second)
		if err != nil {
			return err
		}
		lines := strings.Split(strings.ReplaceAll(string(body), "\r", ""), "\n")
		if len(lines) == 0 || !strings.HasPrefix(strings.TrimSpace(lines[0]), "#EXTM3U") {
			return errors.New("nu e playlist HLS valid")
		}
		// master playlist → varianta cu bandwidth maxim
		best, bestBW := "", -1
		for i, l := range lines {
			if strings.HasPrefix(l, "#EXT-X-STREAM-INF:") {
				bw, _ := strconv.Atoi(parseAttrs(l[18:])["BANDWIDTH"])
				for j := i + 1; j < len(lines); j++ {
					if t := strings.TrimSpace(lines[j]); t != "" && !strings.HasPrefix(t, "#") {
						if bw > bestBW {
							best, bestBW = resolveURL(finalURL, t), bw
						}
						break
					}
				}
			}
		}
		if best != "" {
			plURL = best
			continue
		}
		target, mseq, endlist := 6.0, 0, false
		var segs []hlsSegRef
		var curKey hlsSegRef
		dur := 0.0
		for _, l := range lines {
			l = strings.TrimSpace(l)
			switch {
			case strings.HasPrefix(l, "#EXT-X-TARGETDURATION:"):
				target, _ = strconv.ParseFloat(l[22:], 64)
			case strings.HasPrefix(l, "#EXT-X-MEDIA-SEQUENCE:"):
				mseq, _ = strconv.Atoi(l[22:])
			case strings.HasPrefix(l, "#EXT-X-ENDLIST"):
				endlist = true
			case strings.HasPrefix(l, "#EXT-X-MAP:"):
				return errHLSfMP4
			case strings.HasPrefix(l, "#EXT-X-KEY:"):
				at := parseAttrs(l[11:])
				curKey = hlsSegRef{method: at["METHOD"]}
				if at["URI"] != "" {
					curKey.keyURI = resolveURL(finalURL, at["URI"])
				}
				if iv := strings.TrimPrefix(strings.TrimPrefix(at["IV"], "0x"), "0X"); iv != "" {
					curKey.iv, _ = hex.DecodeString(iv)
				}
			case strings.HasPrefix(l, "#EXTINF:"):
				dur, _ = strconv.ParseFloat(strings.SplitN(l[8:], ",", 2)[0], 64)
			case l != "" && !strings.HasPrefix(l, "#"):
				s := curKey
				s.uri, s.seq, s.dur = resolveURL(finalURL, l), mseq+len(segs), dur
				segs = append(segs, s)
			}
		}
		if len(segs) == 0 {
			if !sleepCtx(ctx, time.Second) {
				return ctx.Err()
			}
			continue
		}
		lastInList := segs[len(segs)-1].seq
		if lastSeq < 0 || lastSeq > lastInList+5 {
			lastSeq = lastInList - 3
		}
		got := false
		for i, s := range segs {
			if s.seq <= lastSeq {
				continue
			}
			data, _, err := httpGet(ctx, s.uri, 30*time.Second)
			if err != nil {
				return err
			}
			if s.method == "AES-128" {
				if data, err = decryptAES(ctx, data, s, keys); err != nil {
					return err
				}
			} else if s.method != "" && s.method != "NONE" {
				return fmt.Errorf("criptare HLS %s nesuportată", s.method)
			}
			lastSeq, got = s.seq, true
			pending := len(segs) - 1 - i
			if pending <= 2 && s.dur > 0 {
				if !pacedPush(ctx, al, data, s.dur*0.95, out) {
					return ctx.Err()
				}
			} else {
				al.Push(data, out)
			}
		}
		if endlist && !got {
			return errors.New("playlist HLS terminat (ENDLIST)")
		}
		wait := time.Second
		if !got {
			wait = time.Duration(math.Max(1, target/2) * float64(time.Second))
		}
		if !sleepCtx(ctx, wait) {
			return ctx.Err()
		}
	}
}

func decryptAES(ctx context.Context, data []byte, s hlsSegRef, cache map[string][]byte) ([]byte, error) {
	key, ok := cache[s.keyURI]
	if !ok {
		k, _, err := httpGet(ctx, s.keyURI, 15*time.Second)
		if err != nil {
			return nil, err
		}
		if len(k) != 16 {
			return nil, errors.New("cheie AES invalidă")
		}
		cache[s.keyURI], key = k, k
	}
	iv := s.iv
	if len(iv) != 16 {
		iv = make([]byte, 16)
		for i := 0; i < 8; i++ {
			iv[15-i] = byte(uint64(s.seq) >> (8 * i))
		}
	}
	if len(data)%16 != 0 {
		return nil, errors.New("segment criptat corupt")
	}
	blk, _ := aes.NewCipher(key)
	cipher.NewCBCDecrypter(blk, iv).CryptBlocks(data, data)
	if p := int(data[len(data)-1]); p > 0 && p <= 16 && p <= len(data) {
		data = data[:len(data)-p]
	}
	return data, nil
}

func pacedPush(ctx context.Context, al *Aligner, data []byte, dur float64, out func([]byte)) bool {
	const step = 50 * time.Millisecond
	slices := int(dur / step.Seconds())
	if slices < 1 {
		al.Push(data, out)
		return true
	}
	chunk := (len(data)/slices/tsSize + 1) * tsSize
	t := time.NewTicker(step)
	defer t.Stop()
	for off := 0; off < len(data); off += chunk {
		end := off + chunk
		if end > len(data) {
			end = len(data)
		}
		al.Push(data[off:end], out)
		if end < len(data) {
			select {
			case <-ctx.Done():
				return false
			case <-t.C:
			}
		}
	}
	return true
}

type tailBuf struct {
	mu sync.Mutex
	b  []byte
}

func (t *tailBuf) Write(p []byte) (int, error) {
	t.mu.Lock()
	t.b = append(t.b, p...)
	if len(t.b) > 4096 {
		t.b = t.b[len(t.b)-4096:]
	}
	t.mu.Unlock()
	return len(p), nil
}

func (t *tailBuf) last() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	ls := strings.Split(strings.TrimSpace(string(t.b)), "\n")
	return strings.TrimSpace(ls[len(ls)-1])
}

func readExec(ctx context.Context, name string, args []string, out func([]byte)) error {
	if _, err := exec.LookPath(name); err != nil {
		return fmt.Errorf("%s nu a fost găsit — instalează-l sau pune-l în folderul StreamHub", name)
	}
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.SysProcAttr = childProcAttr()
	cmd.WaitDelay = 3 * time.Second
	tb := &tailBuf{}
	cmd.Stderr = tb
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	err = readStream(ctx, stdout, out)
	if cmd.Process != nil {
		cmd.Process.Kill()
	}
	cmd.Wait()
	if l := tb.last(); l != "" && ctx.Err() == nil {
		return fmt.Errorf("%s: %s", name, l)
	}
	return err
}

func hasSRTffmpeg() bool {
	o, err := exec.Command("ffmpeg", "-hide_banner", "-protocols").Output()
	return err == nil && strings.Contains(string(o), "srt")
}

func openInput(ctx context.Context, src string, out func([]byte)) error {
	src = strings.TrimSpace(src)
	// opțiuni stil Astra după '#', ex. udp://239.1.1.1:1234#pnr=101
	if base, opts, ok := strings.Cut(src, "#"); ok {
		src = base
		for _, o := range strings.Split(opts, "&") {
			if v, ok := strings.CutPrefix(o, "pnr="); ok {
				n, err := strconv.Atoi(v)
				if err != nil || n <= 0 || n > 65535 {
					return fmt.Errorf("pnr invalid: %s", v)
				}
				f, next := newPNRFilter(n), out
				out = func(b []byte) {
					if fb := f.Filter(b); len(fb) > 0 {
						next(fb)
					}
				}
			}
		}
	}
	u, err := url.Parse(src)
	if err != nil {
		return fmt.Errorf("URL invalid: %v", err)
	}
	switch strings.ToLower(u.Scheme) {
	case "udp", "rtp":
		return readUDP(ctx, u, out)
	case "http", "https":
		return readHTTP(ctx, src, out)
	case "srt":
		// copiere byte-cu-byte a TS-ului (PID-uri, PSI/SI, teletext păstrate integral)
		if _, err := exec.LookPath("srt-live-transmit"); err == nil {
			return readExec(ctx, "srt-live-transmit", []string{src, "file://con"}, out)
		}
		if hasSRTffmpeg() {
			return readExec(ctx, "ffmpeg", []string{"-hide_banner", "-loglevel", "error", "-f", "data", "-i", src, "-map", "0", "-c", "copy", "-f", "data", "pipe:1"}, out)
		}
		return errors.New("pentru SRT instalează srt-tools sau ffmpeg cu suport SRT")
	case "rtmp", "rtmps", "rtmp-listen":
		// RTMP transportă FLV (nu are PID-uri) → mux în TS cu PID-uri fixe
		in := []string{"-hide_banner", "-loglevel", "error", "-rw_timeout", "15000000"}
		if u.Scheme == "rtmp-listen" {
			src = "rtmp://" + strings.TrimPrefix(src, "rtmp-listen://")
			in = []string{"-hide_banner", "-loglevel", "error", "-listen", "1"}
		}
		args := append(in, "-i", src, "-map", "0", "-c", "copy", "-f", "mpegts",
			"-mpegts_pmt_start_pid", "0x1000", "-mpegts_start_pid", "0x100", "pipe:1")
		return readExec(ctx, "ffmpeg", args, out)
	}
	return fmt.Errorf("protocol nesuportat: %s", u.Scheme)
}

// ============================== CHANNEL ==============================

type Subscriber struct {
	ch    chan []byte
	addr  string
	start time.Time
	ready bool // a primit deja un keyframe
	ua    string
	bytes atomic.Uint64
	kbps  atomic.Int64
	prev  uint64
}

type ClientInfo struct {
	Addr  string `json:"addr"`
	Type  string `json:"type"`
	Secs  int64  `json:"secs"`
	Kbps  int    `json:"kbps"`
	UA    string `json:"ua"`
	Bytes uint64 `json:"bytes"`
}

type hlsClient struct {
	first time.Time
	ua    string
	seen  time.Time
	bytes uint64
	prev  uint64
	kbps  int
}

type Channel struct {
	cfg    ChannelConfig
	ctx    context.Context
	cancel context.CancelFunc
	an     *Analyzer
	hls    *HLSSeg
	udp    *UDPOut

	subMu    sync.Mutex
	subs     map[*Subscriber]struct{}
	hlsSeen  map[string]*hlsClient
	outBytes atomic.Uint64 // tot ce pleacă: HTTP + HLS + UDP
	outPrev  uint64
	outKbps  atomic.Int64

	stMu      sync.Mutex
	online    bool
	activeIdx int
	activeURL string
	lastErr   string
	since     time.Time
	switches  int
	lastData  atomic.Int64
}

var errSwitchPrimary = errors.New("revenire pe sursa principală")

func NewChannel(cfg ChannelConfig, hlsSeg, hlsWin int) *Channel {
	c := &Channel{cfg: cfg, an: NewAnalyzer(), subs: map[*Subscriber]struct{}{}, hlsSeen: map[string]*hlsClient{}}
	if cfg.HLS {
		c.hls = NewHLS(hlsSeg, hlsWin)
	}
	c.ctx, c.cancel = context.WithCancel(context.Background())
	if cfg.UDP != "" {
		o, err := NewUDPOut(cfg.UDP)
		if err != nil {
			c.lastErr = err.Error()
			log.Printf("[%s] %v", cfg.ID, err)
		} else {
			o.count = &c.outBytes
			c.udp = o
		}
	}
	go c.run()
	go c.ticker()
	return c
}

func (c *Channel) Stop() {
	c.cancel()
	if c.udp != nil {
		c.udp.Close()
	}
	c.subMu.Lock()
	for s := range c.subs {
		close(s.ch)
		delete(c.subs, s)
	}
	c.subMu.Unlock()
}

func (c *Channel) ticker() {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-t.C:
			c.an.Tick()
			ob := c.outBytes.Load()
			c.outKbps.Store(int64((ob - c.outPrev) * 8 / 1000))
			c.outPrev = ob
			c.subMu.Lock()
			for s := range c.subs {
				b := s.bytes.Load()
				s.kbps.Store(int64((b - s.prev) * 8 / 1000))
				s.prev = b
			}
			for ip, h := range c.hlsSeen {
				if time.Since(h.seen) > 30*time.Second {
					delete(c.hlsSeen, ip)
					continue
				}
				// HLS vine în rafale (segmente) → medie pe 5s
				inst := int((h.bytes - h.prev) * 8 / 1000)
				h.kbps = (h.kbps*4 + inst) / 5
				h.prev = h.bytes
			}
			c.subMu.Unlock()
		}
	}
}

func (c *Channel) run() {
	idx := 0
	lastLog := ""
	for c.ctx.Err() == nil {
		inputs := c.cfg.Inputs
		if len(inputs) == 0 {
			c.setErr("nicio intrare configurată")
			sleepCtx(c.ctx, 5*time.Second)
			continue
		}
		if idx >= len(inputs) {
			idx = 0
		}
		runStart := time.Now()
		err := c.runInput(idx, inputs[idx])
		if c.ctx.Err() != nil {
			return
		}
		c.stMu.Lock()
		if c.since.After(runStart) {
			lastLog = "" // a fost online în rularea asta → logăm căderea
		}
		c.stMu.Unlock()
		if err == nil || err == errSwitchPrimary {
			lastLog = ""
		}
		if err == errSwitchPrimary {
			log.Printf("[%s] sursa principală e din nou activă, revin pe ea", c.cfg.ID)
			idx = 0
			continue
		}
		c.stMu.Lock()
		c.online = false
		if err != nil {
			c.lastErr = err.Error()
		}
		c.stMu.Unlock()
		if msg := fmt.Sprint(err); msg != lastLog {
			log.Printf("[%s] intrarea #%d (%s) a căzut: %v", c.cfg.ID, idx+1, inputs[idx], err)
			lastLog = msg
		}
		if len(inputs) > 1 {
			idx = (idx + 1) % len(inputs)
			c.stMu.Lock()
			c.switches++
			c.stMu.Unlock()
		}
		wait := 500 * time.Millisecond
		if idx == 0 {
			wait = 2 * time.Second
		}
		sleepCtx(c.ctx, wait)
	}
}

func (c *Channel) setErr(e string) {
	c.stMu.Lock()
	c.lastErr = e
	c.online = false
	c.stMu.Unlock()
}

func (c *Channel) runInput(idx int, src string) error {
	ictx, icancel := context.WithCancel(c.ctx)
	defer icancel()
	c.stMu.Lock()
	c.activeIdx, c.activeURL = idx, src
	c.stMu.Unlock()
	c.an.Reset()
	if c.hls != nil {
		c.hls.Discontinuity()
	}
	startAt := time.Now()
	c.lastData.Store(0)
	var reason atomic.Value
	go func() {
		t := time.NewTicker(time.Second)
		defer t.Stop()
		lastProbe := time.Now()
		for {
			select {
			case <-ictx.Done():
				return
			case <-t.C:
			}
			ld := c.lastData.Load()
			if ld == 0 {
				// fără backup: așteptăm sursa oricât (ex. encoder RTMP/SRT care încă nu s-a conectat)
				if len(c.cfg.Inputs) > 1 && time.Since(startAt) > 20*time.Second {
					reason.Store(errors.New("nu sosesc date de la sursă"))
					icancel()
					return
				}
				continue
			}
			age := time.Since(time.Unix(0, ld))
			c.stMu.Lock()
			wasOnline := c.online
			c.online = age < 3*time.Second
			if c.online && !wasOnline {
				c.since = time.Now()
				c.lastErr = ""
				log.Printf("[%s] online pe intrarea #%d", c.cfg.ID, idx+1)
			}
			c.stMu.Unlock()
			limit := 10 * time.Second
			if len(c.cfg.Inputs) > 1 {
				limit = 5 * time.Second // există backup → comutare rapidă
			}
			if age > limit {
				reason.Store(fmt.Errorf("sursa nu mai trimite date (timeout %v)", limit))
				icancel()
				return
			}
			if idx > 0 && time.Since(lastProbe) > 60*time.Second {
				lastProbe = time.Now()
				if probe(ictx, c.cfg.Inputs[0]) {
					reason.Store(errSwitchPrimary)
					icancel()
					return
				}
			}
		}
	}()
	err := openInput(ictx, src, c.onData)
	if r, ok := reason.Load().(error); ok {
		return r
	}
	return err
}

func probe(ctx context.Context, src string) bool {
	pctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	var n atomic.Int64
	openInput(pctx, src, func(b []byte) {
		if n.Add(int64(len(b)/tsSize)) > 1500 {
			cancel()
		}
	})
	return n.Load() > 1500
}

func (c *Channel) onData(chunk []byte) {
	c.lastData.Store(time.Now().UnixNano())
	keyOff := -1
	var keyPSI []byte
	for i := 0; i+tsSize <= len(chunk); i += tsSize {
		p := chunk[i : i+tsSize]
		inf := c.an.Process(p)
		if inf.start && inf.key && keyOff < 0 {
			keyOff = i
			keyPSI = c.an.PSIPackets() // PAT/PMT valabile exact înainte de keyframe → CC continuu
		}
		if c.hls != nil {
			c.hls.Write(p, inf, c.an)
		}
		if c.udp != nil {
			c.udp.WritePkt(p)
		}
	}
	if c.cfg.HTTP {
		c.subMu.Lock()
		for s := range c.subs {
			out := chunk
			if !s.ready {
				// clientul nou primește date începând de la un keyframe → pornire fără artefacte
				if keyOff >= 0 {
					out = append(append(make([]byte, 0, len(keyPSI)+len(chunk)-keyOff), keyPSI...), chunk[keyOff:]...)
				} else if time.Since(s.start) < 5*time.Second {
					continue
				} else {
					out = append(c.an.PSIPackets(), chunk...)
				}
				s.ready = true
			}
			select {
			case s.ch <- out:
			default: // client prea lent → deconectat
				close(s.ch)
				delete(c.subs, s)
			}
		}
		c.subMu.Unlock()
	}
}

func (c *Channel) hlsTouch(ip, ua string, n uint64) {
	c.subMu.Lock()
	key := ip + "|" + ua // mai mulți playeri în spatele aceluiași IP
	h := c.hlsSeen[key]
	if h == nil {
		if n == 0 {
			// doar playlist cerut, fără segmente → nu e încă un client real
			c.subMu.Unlock()
			return
		}
		h = &hlsClient{first: time.Now(), ua: ua}
		c.hlsSeen[key] = h
	}
	h.seen = time.Now()
	h.bytes += n
	c.subMu.Unlock()
}

func (c *Channel) addSub(s *Subscriber) {
	c.subMu.Lock()
	c.subs[s] = struct{}{}
	c.subMu.Unlock()
}

func (c *Channel) removeSub(s *Subscriber) {
	c.subMu.Lock()
	if _, ok := c.subs[s]; ok {
		close(s.ch)
		delete(c.subs, s)
	}
	c.subMu.Unlock()
}

type ChanStatus struct {
	ChannelConfig
	Running   bool         `json:"running"`
	Online    bool         `json:"online"`
	Input     string       `json:"input"`
	InputIdx  int          `json:"input_idx"`
	Kbps      int          `json:"kbps"`
	OutKbps   int          `json:"out_kbps"`
	CC        uint64       `json:"cc"`
	Scrambled bool         `json:"scrambled"`
	Clients   []ClientInfo `json:"clients"`
	Uptime    int64        `json:"uptime"`
	Service   string       `json:"service"`
	Provider  string       `json:"provider"`
	Error     string       `json:"error"`
	PIDs      []PIDInfo    `json:"pids"`
	HLSSegs   int          `json:"hls_segs"`
	Switches  int          `json:"switches"`
}

func (c *Channel) Status() ChanStatus {
	s := ChanStatus{ChannelConfig: c.cfg, Running: true}
	a := c.an.Snapshot()
	c.stMu.Lock()
	s.Online, s.Input, s.InputIdx, s.Error, s.Switches = c.online, c.activeURL, c.activeIdx, c.lastErr, c.switches
	if c.online {
		s.Uptime = int64(time.Since(c.since).Seconds())
	}
	c.stMu.Unlock()
	if s.Online {
		s.Kbps, s.Scrambled, s.Service, s.Provider, s.PIDs = a.Kbps, a.Scrambled, a.Service, a.Provider, a.PIDs
	}
	s.CC = a.CC
	s.OutKbps = int(c.outKbps.Load())
	c.subMu.Lock()
	s.Clients = []ClientInfo{}
	for sub := range c.subs {
		s.Clients = append(s.Clients, ClientInfo{Addr: sub.addr, Type: "HTTP", Secs: int64(time.Since(sub.start).Seconds()), Kbps: int(sub.kbps.Load()), UA: sub.ua, Bytes: sub.bytes.Load()})
	}
	for key, h := range c.hlsSeen {
		s.Clients = append(s.Clients, ClientInfo{Addr: strings.SplitN(key, "|", 2)[0], Type: "HLS", Secs: int64(time.Since(h.first).Seconds()), Kbps: h.kbps, UA: h.ua, Bytes: h.bytes})
	}
	sort.Slice(s.Clients, func(i, j int) bool { return s.Clients[i].Secs > s.Clients[j].Secs })
	c.subMu.Unlock()
	if c.hls != nil {
		s.HLSSegs = c.hls.Count()
	}
	return s
}

// ============================== SERVER ==============================

type Server struct {
	mu       sync.RWMutex
	cfg      *Config
	cfgPath  string
	channels map[string]*Channel
}

var idRe = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)

func NewServer(path string) (*Server, error) {
	s := &Server{cfgPath: path, channels: map[string]*Channel{}}
	b, err := os.ReadFile(path)
	cfg := &Config{}
	if errors.Is(err, os.ErrNotExist) {
		cfg = &Config{Listen: ":4000", AdminUser: "admin", AdminPass: randHex(6), Tokens: []string{}, HLSSegment: 4, HLSWindow: 6}
		s.cfg = cfg
		if err := s.save(); err != nil {
			return nil, err
		}
		log.Printf("config nou creat: %s  (utilizator: admin  parolă: %s)", path, cfg.AdminPass)
	} else if err != nil {
		return nil, err
	} else if err := json.Unmarshal(b, cfg); err != nil {
		return nil, fmt.Errorf("config invalid: %v", err)
	}
	if cfg.Listen == "" {
		cfg.Listen = ":4000"
	}
	if cfg.HLSSegment <= 0 {
		cfg.HLSSegment = 4
	}
	if cfg.HLSWindow <= 0 {
		cfg.HLSWindow = 6
	}
	if cfg.Tokens == nil {
		cfg.Tokens = []string{}
	}
	s.cfg = cfg
	for _, ch := range cfg.Channels {
		if ch.Enabled {
			s.channels[ch.ID] = NewChannel(*ch, cfg.HLSSegment, cfg.HLSWindow)
		}
	}
	return s, nil
}

func (s *Server) save() error {
	b, _ := json.MarshalIndent(s.cfg, "", "  ")
	tmp := s.cfgPath + ".tmp"
	if err := os.WriteFile(tmp, b, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, s.cfgPath)
}

// channel: potrivire exactă, apoi fără diferență între litere mari/mici (/HD365 = /hd365)
func (s *Server) channel(id string) *Channel {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if c := s.channels[id]; c != nil {
		return c
	}
	for k, c := range s.channels {
		if strings.EqualFold(k, id) {
			return c
		}
	}
	return nil
}

// handleShort: link scurt, compatibil Astra
//
//	/hd365        → HTTP-TS   (și /hd365.ts)
//	/hd365.m3u8   → HLS
func (s *Server) handleShort(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if base, ok := strings.CutSuffix(id, ".m3u8"); ok {
		c := s.channel(base)
		if c == nil || c.hls == nil {
			http.Error(w, "canal inexistent", 404)
			return
		}
		s.serveHLS(w, r, c, "index.m3u8", url.PathEscape(base)+"/")
		return
	}
	s.handlePlay(w, r)
}

// clientIP: IP-ul real al clientului. Headerele de proxy sunt crezute doar
// când cererea vine de pe aceeași mașină (nginx local), altfel ar putea fi falsificate.
func clientIP(r *http.Request) string {
	h, _, _ := net.SplitHostPort(r.RemoteAddr)
	if ip := net.ParseIP(h); ip != nil && ip.IsLoopback() {
		if x := r.Header.Get("X-Real-IP"); x != "" {
			return strings.TrimSpace(x)
		}
		if x := r.Header.Get("X-Forwarded-For"); x != "" {
			return strings.TrimSpace(strings.Split(x, ",")[0])
		}
	}
	return h
}

func (s *Server) allowed(r *http.Request, c *Channel) bool {
	if c.cfg.Public {
		return true
	}
	s.mu.RLock()
	toks := s.cfg.Tokens
	s.mu.RUnlock()
	if len(toks) == 0 {
		return true
	}
	t := []byte(r.URL.Query().Get("token"))
	for _, k := range toks {
		if k != "" && subtle.ConstantTimeCompare([]byte(k), t) == 1 {
			return true
		}
	}
	return false
}

func (s *Server) handlePlay(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSuffix(r.PathValue("id"), ".ts")
	c := s.channel(id)
	if c == nil || !c.cfg.HTTP {
		http.Error(w, "canal inexistent", 404)
		return
	}
	if !s.allowed(r, c) {
		http.Error(w, "acces interzis", 403)
		return
	}
	sub := &Subscriber{ch: make(chan []byte, 4096), addr: clientIP(r), start: time.Now(), ua: r.UserAgent()}
	c.addSub(sub)
	defer c.removeSub(sub)
	h := w.Header()
	h.Set("Content-Type", "video/mp2t")
	h.Set("Cache-Control", "no-cache")
	h.Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(200)
	fl, _ := w.(http.Flusher)
	if fl != nil {
		fl.Flush()
	}
	for {
		select {
		case <-r.Context().Done():
			return
		case b, ok := <-sub.ch:
			if !ok {
				return
			}
			n, err := w.Write(b)
			sub.bytes.Add(uint64(n))
			c.outBytes.Add(uint64(n))
			if err != nil {
				return
			}
		drain:
			for i := 0; i < 64; i++ {
				select {
				case b, ok := <-sub.ch:
					if !ok {
						return
					}
					n, err := w.Write(b)
					sub.bytes.Add(uint64(n))
					c.outBytes.Add(uint64(n))
					if err != nil {
						return
					}
				default:
					break drain
				}
			}
			if fl != nil {
				fl.Flush()
			}
		}
	}
}

func (s *Server) handleHLS(w http.ResponseWriter, r *http.Request) {
	c := s.channel(r.PathValue("id"))
	if c == nil || c.hls == nil {
		http.Error(w, "canal inexistent", 404)
		return
	}
	s.serveHLS(w, r, c, r.PathValue("file"), "")
}

func (s *Server) serveHLS(w http.ResponseWriter, r *http.Request, c *Channel, file, prefix string) {
	if !s.allowed(r, c) {
		http.Error(w, "acces interzis", 403)
		return
	}
	w.Header().Set("Access-Control-Allow-Origin", "*")
	if file == "index.m3u8" || file == "playlist.m3u8" || file == "mono.m3u8" {
		q := ""
		if t := r.URL.Query().Get("token"); t != "" {
			q = "?token=" + url.QueryEscape(t)
		}
		pl, ok := c.hls.Playlist(prefix, q)
		if !ok {
			http.Error(w, "stream indisponibil", 503)
			return
		}
		c.hlsTouch(clientIP(r), r.UserAgent(), 0)
		w.Header().Set("Content-Type", "application/vnd.apple.mpegurl")
		w.Header().Set("Cache-Control", "no-cache")
		w.Write(pl)
		return
	}
	seq, err := strconv.Atoi(strings.TrimSuffix(file, ".ts"))
	if err != nil {
		http.Error(w, "inexistent", 404)
		return
	}
	data := c.hls.Get(seq)
	if data == nil {
		http.Error(w, "segment expirat", 404)
		return
	}
	w.Header().Set("Content-Type", "video/mp2t")
	w.Header().Set("Cache-Control", "max-age=60")
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	n, _ := w.Write(data)
	c.outBytes.Add(uint64(n))
	c.hlsTouch(clientIP(r), r.UserAgent(), uint64(n))
}

func (s *Server) admin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		s.mu.RLock()
		au, ap := s.cfg.AdminUser, s.cfg.AdminPass
		s.mu.RUnlock()
		if !ok || subtle.ConstantTimeCompare([]byte(u), []byte(au)) != 1 || subtle.ConstantTimeCompare([]byte(p), []byte(ap)) != 1 {
			w.Header().Set("WWW-Authenticate", `Basic realm="StreamHub"`)
			http.Error(w, "autentificare necesară", 401)
			return
		}
		next(w, r)
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(v)
}

func (s *Server) apiStatus(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	list := make([]ChanStatus, 0, len(s.cfg.Channels))
	for _, cc := range s.cfg.Channels {
		if c := s.channels[cc.ID]; c != nil {
			list = append(list, c.Status())
		} else {
			list = append(list, ChanStatus{ChannelConfig: *cc, Clients: []ClientInfo{}})
		}
	}
	s.mu.RUnlock()
	writeJSON(w, map[string]any{"version": version, "uptime": int64(time.Since(startTime).Seconds()), "channels": list})
}

func (s *Server) apiConfig(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	writeJSON(w, map[string]any{"tokens": s.cfg.Tokens, "hls_segment": s.cfg.HLSSegment, "hls_window": s.cfg.HLSWindow, "channels": s.cfg.Channels})
}

func (s *Server) apiChannelSave(w http.ResponseWriter, r *http.Request) {
	var in ChannelConfig
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&in); err != nil {
		http.Error(w, "JSON invalid", 400)
		return
	}
	in.ID = strings.TrimSpace(in.ID)
	if !idRe.MatchString(in.ID) {
		http.Error(w, "ID invalid (litere, cifre, - sau _)", 400)
		return
	}
	switch strings.ToLower(in.ID) {
	case "api", "hls", "play", "favicon":
		http.Error(w, "ID rezervat: "+in.ID, 400)
		return
	}
	var ins []string
	for _, x := range in.Inputs {
		if x = strings.TrimSpace(x); x != "" {
			if _, err := url.Parse(x); err != nil {
				http.Error(w, "intrare invalidă: "+x, 400)
				return
			}
			ins = append(ins, x)
		}
	}
	in.Inputs = ins
	in.UDP = strings.TrimSpace(in.UDP)
	if in.UDP != "" {
		if u, err := url.Parse(in.UDP); err != nil || (u.Scheme != "udp" && u.Scheme != "rtp") {
			http.Error(w, "ieșire UDP invalidă (ex: udp://239.1.1.1:1234)", 400)
			return
		}
	}
	old := r.URL.Query().Get("old") // gol = canal nou
	creating := old == ""
	s.mu.Lock()
	defer s.mu.Unlock()
	pos := -1
	for i, c := range s.cfg.Channels {
		if !creating && c.ID == old {
			pos = i
		} else if c.ID == in.ID {
			http.Error(w, "există deja un canal cu ID-ul "+in.ID, 409)
			return
		}
	}
	if !creating && pos < 0 {
		http.Error(w, "canalul "+old+" nu mai există", 404)
		return
	}
	if c := s.channels[old]; c != nil && !creating {
		c.Stop()
		delete(s.channels, old)
	}
	cp := in
	if pos >= 0 {
		s.cfg.Channels[pos] = &cp
	} else {
		s.cfg.Channels = append(s.cfg.Channels, &cp)
	}
	if cp.Enabled {
		s.channels[cp.ID] = NewChannel(cp, s.cfg.HLSSegment, s.cfg.HLSWindow)
	}
	if err := s.save(); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	log.Printf("canal salvat: %s", cp.ID)
	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) apiChannelDelete(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	s.mu.Lock()
	defer s.mu.Unlock()
	if c := s.channels[id]; c != nil {
		c.Stop()
		delete(s.channels, id)
	}
	out := s.cfg.Channels[:0]
	for _, c := range s.cfg.Channels {
		if c.ID != id {
			out = append(out, c)
		}
	}
	s.cfg.Channels = out
	s.save()
	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) apiRestart(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, cc := range s.cfg.Channels {
		if cc.ID == id && cc.Enabled {
			if c := s.channels[id]; c != nil {
				c.Stop()
			}
			s.channels[id] = NewChannel(*cc, s.cfg.HLSSegment, s.cfg.HLSWindow)
		}
	}
	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) apiSettings(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Tokens     []string `json:"tokens"`
		HLSSegment int      `json:"hls_segment"`
		HLSWindow  int      `json:"hls_window"`
		AdminPass  string   `json:"admin_pass"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&in); err != nil {
		http.Error(w, "JSON invalid", 400)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	toks := []string{}
	for _, t := range in.Tokens {
		if t = strings.TrimSpace(t); t != "" {
			toks = append(toks, t)
		}
	}
	s.cfg.Tokens = toks
	if p := strings.TrimSpace(in.AdminPass); p != "" {
		if len(p) < 6 {
			http.Error(w, "parola trebuie să aibă minim 6 caractere", 400)
			return
		}
		s.cfg.AdminPass = p
	}
	hlsChanged := false
	if in.HLSSegment >= 1 && in.HLSSegment <= 20 && in.HLSSegment != s.cfg.HLSSegment {
		s.cfg.HLSSegment, hlsChanged = in.HLSSegment, true
	}
	if in.HLSWindow >= 2 && in.HLSWindow <= 30 && in.HLSWindow != s.cfg.HLSWindow {
		s.cfg.HLSWindow, hlsChanged = in.HLSWindow, true
	}
	if hlsChanged {
		for _, cc := range s.cfg.Channels {
			if c := s.channels[cc.ID]; c != nil && cc.HLS {
				c.Stop()
				s.channels[cc.ID] = NewChannel(*cc, s.cfg.HLSSegment, s.cfg.HLSWindow)
			}
		}
	}
	if err := s.save(); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

func main() {
	cfgPath := flag.String("config", defaultConfigPath(), "fișierul de configurare")
	install := flag.Bool("install", false, "Windows: pornire automată cu sistemul (rulează ca serviciu)")
	uninstall := flag.Bool("uninstall", false, "Windows: elimină pornirea automată")
	flag.Parse()
	log.SetFlags(log.LstdFlags)
	if *install || *uninstall {
		if err := platformService(*install, *cfgPath); err != nil {
			fatal(err)
		}
		return
	}
	platformInit()
	_, statErr := os.Stat(*cfgPath)
	firstRun := errors.Is(statErr, os.ErrNotExist)
	s, err := NewServer(*cfgPath)
	if err != nil {
		fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /play/{id}", s.handlePlay)
	mux.HandleFunc("GET /hls/{id}/{file}", s.handleHLS)
	mux.HandleFunc("GET /{id}", s.handleShort)      // http://server:4000/hd365  (+ .m3u8)
	mux.HandleFunc("GET /{id}/{file}", s.handleHLS) // http://server:4000/hd365/index.m3u8
	mux.HandleFunc("GET /api/status", s.admin(s.apiStatus))
	mux.HandleFunc("GET /api/config", s.admin(s.apiConfig))
	mux.HandleFunc("POST /api/channel", s.admin(s.apiChannelSave))
	mux.HandleFunc("DELETE /api/channel", s.admin(s.apiChannelDelete))
	mux.HandleFunc("POST /api/restart", s.admin(s.apiRestart))
	mux.HandleFunc("POST /api/settings", s.admin(s.apiSettings))
	mux.HandleFunc("GET /{$}", s.admin(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(uiHTML))
	}))
	log.Printf("StreamHub %s ascultă pe %s (%d canale)", version, s.cfg.Listen, len(s.cfg.Channels))
	ln, err := net.Listen("tcp", s.cfg.Listen)
	if err != nil {
		fatal(fmt.Errorf("nu pot asculta pe %s: %v (portul e ocupat? schimbă \"listen\" în %s)", s.cfg.Listen, err, *cfgPath))
	}
	if firstRun {
		port := s.cfg.Listen[strings.LastIndex(s.cfg.Listen, ":")+1:]
		openBrowser("http://127.0.0.1:" + port + "/")
	}
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	for _, extra := range s.cfg.ListenExtra {
		l2, err := net.Listen("tcp", extra)
		if err != nil {
			fatal(fmt.Errorf("nu pot asculta pe %s: %v", extra, err))
		}
		log.Printf("ascult și pe %s", extra)
		go func() { fatal(srv.Serve(l2)) }()
	}
	fatal(srv.Serve(ln))
}
