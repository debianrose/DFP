package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/progress"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/quic-go/quic-go"
)

var (
	titleStyle   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#00FF00"))
	successStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#00FF00"))
	infoStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("#00FFFF"))
	dimStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("#666666"))
)

const (
	CompressLimit = 10 * 1024 * 1024 // 10MB
)

type Srv struct {
	port   uint16
	tls    *tls.Config
	crypto *Crypto
	mu     sync.RWMutex
	files  []string
	stats  map[string]*Stat
}

type Stat struct {
	name string
	size int64
	up   time.Time
}

func NewSrv(port uint16, pass string) (*Srv, error) {
	tls, _ := GenTLS()
	os.MkdirAll(STORE, 0755)
	return &Srv{
		port:   port,
		tls:    tls,
		crypto: NewCrypto(pass),
		files:  []string{},
		stats:  make(map[string]*Stat),
	}, nil
}

func (s *Srv) Run(ui *SrvUI) error {
	addr := fmt.Sprintf("0.0.0.0:%d", s.port)
	l, err := quic.ListenAddr(addr, s.tls, QCfg())
	if err != nil {
		return err
	}
	defer l.Close()

	ui.Log(fmt.Sprintf("🚀 Server started on %s", addr))
	ui.Log(fmt.Sprintf("🔒 Encryption: ChaCha20-Poly1305 (parallel)"))
	ui.Log(fmt.Sprintf("📦 Compress: files < %d MB", CompressLimit/1024/1024))
	s.scan()

	for {
		conn, err := l.Accept(context.Background())
		if err != nil {
			continue
		}
		go s.handle(conn, ui)
	}
}

func (s *Srv) scan() {
	entries, _ := os.ReadDir(STORE)
	s.mu.Lock()
	s.files = []string{}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), EXT) {
			name := strings.TrimSuffix(e.Name(), EXT)
			s.files = append(s.files, name)
			info, _ := e.Info()
			s.stats[name] = &Stat{name: name, size: info.Size(), up: info.ModTime()}
		}
	}
	s.mu.Unlock()
}

func (s *Srv) handle(conn quic.Connection, ui *SrvUI) {
	defer conn.CloseWithError(0, "")
	st, _ := conn.AcceptStream(context.Background())
	defer st.Close()

	cmd := make([]byte, 1)
	io.ReadFull(st, cmd)

	switch cmd[0] {
	case 0:
		s.upload(st, ui)
	case 1:
		s.download(st, ui)
	case 2:
		s.list(st, ui)
	}
}

func (s *Srv) upload(st quic.Stream, ui *SrvUI) {
	var nLen uint32
	binary.Read(st, binary.BigEndian, &nLen)
	nb := make([]byte, nLen)
	io.ReadFull(st, nb)
	name := string(nb)

	var sz uint64
	binary.Read(st, binary.BigEndian, &sz)

	ui.Log(fmt.Sprintf("⬇ Receiving: %s (%d bytes)", name, sz))

	buf := bytes.NewBuffer(make([]byte, 0, sz))
	var rcv uint64
	tmp := make([]byte, CHUNK)
	start := time.Now()

	for rcv < sz {
		n, err := st.Read(tmp)
		if err != nil {
			if err != io.EOF {
				ui.Log(fmt.Sprintf("❌ Error receiving: %s", err))
			}
			break
		}
		if n == 0 {
			break
		}
		buf.Write(tmp[:n])
		rcv += uint64(n)
		ui.Prog(float64(rcv) / float64(sz))
	}

	data := buf.Bytes()
	
	if uint64(len(data)) != sz {
		ui.Log(fmt.Sprintf("⚠️ Size mismatch: got %d, expected %d", len(data), sz))
	}
	
	compress := len(data) <= CompressLimit
	
	procStart := time.Now()
	var processed []byte
	
	if compress {
		ui.Log(fmt.Sprintf("📦 Compressing %s...", name))
		processed = Zip(data)
	} else {
		processed = data
	}
	
	ui.Log(fmt.Sprintf("🔐 Encrypting %s...", name))
	enc, err := s.crypto.Enc(processed)
	if err != nil {
		ui.Log(fmt.Sprintf("❌ Encryption failed: %s", err))
		st.Write([]byte("ER"))
		return
	}
	
	procTime := time.Since(procStart)

	path := filepath.Join(STORE, name+EXT)
	if err := os.WriteFile(path, enc, 0600); err != nil {
		ui.Log(fmt.Sprintf("❌ Save failed: %s", err))
		st.Write([]byte("ER"))
		return
	}

	s.scan()
	duration := time.Since(start)
	ratio := float64(len(data)) / float64(len(enc))
	speed := float64(len(data)) / duration.Seconds() / 1024 / 1024
	
	ui.Log(fmt.Sprintf("✅ %s saved (%.2fx, proc: %v, %.2f MB/s)", name, ratio, procTime.Round(time.Millisecond), speed))
	
	st.Write([]byte("OK"))
	time.Sleep(100 * time.Millisecond)
}

func (s *Srv) download(st quic.Stream, ui *SrvUI) {
	var nLen uint32
	binary.Read(st, binary.BigEndian, &nLen)
	nb := make([]byte, nLen)
	io.ReadFull(st, nb)
	name := string(nb)

	ui.Log(fmt.Sprintf("⬆ Sending: %s", name))

	path := filepath.Join(STORE, name+EXT)
	enc, err := os.ReadFile(path)
	if err != nil {
		ui.Log(fmt.Sprintf("❌ File not found: %s", name))
		binary.Write(st, binary.BigEndian, uint64(0))
		return
	}

	start := time.Now()
	ui.Log(fmt.Sprintf("🔓 Decrypting %s...", name))
	processed, err := s.crypto.Dec(enc)
	if err != nil {
		ui.Log(fmt.Sprintf("❌ Decryption failed: %s", err))
		binary.Write(st, binary.BigEndian, uint64(0))
		return
	}
	
	ui.Log(fmt.Sprintf("📦 Decompressing %s...", name))
	data, err := Unzip(processed)
	if err != nil {
		ui.Log(fmt.Sprintf("❌ Decompression failed: %s", err))
		binary.Write(st, binary.BigEndian, uint64(0))
		return
	}
	
	procTime := time.Since(start)

	binary.Write(st, binary.BigEndian, uint64(len(data)))

	var sent uint64
	for sent < uint64(len(data)) {
		end := sent + CHUNK
		if end > uint64(len(data)) {
			end = uint64(len(data))
		}
		n, err := st.Write(data[sent:end])
		if err != nil {
			ui.Log(fmt.Sprintf("❌ Send error: %s", err))
			return
		}
		sent += uint64(n)
		ui.Prog(float64(sent) / float64(len(data)))
	}

	time.Sleep(100 * time.Millisecond)

	duration := time.Since(start)
	speed := float64(len(data)) / duration.Seconds() / 1024 / 1024
	ui.Log(fmt.Sprintf("✅ %s sent (proc: %v, %.2f MB/s)", name, procTime.Round(time.Millisecond), speed))
}

func (s *Srv) list(st quic.Stream, ui *SrvUI) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	binary.Write(st, binary.BigEndian, uint32(len(s.files)))
	for _, f := range s.files {
		stat := s.stats[f]
		binary.Write(st, binary.BigEndian, uint32(len(f)))
		st.Write([]byte(f))
		binary.Write(st, binary.BigEndian, uint64(stat.size))
	}
}

func (s *Srv) Files() []list.Item {
	s.mu.RLock()
	defer s.mu.RUnlock()

	items := []list.Item{}
	for _, f := range s.files {
		stat := s.stats[f]
		items = append(items, FileItem{
			Name: f,
			Size: stat.size,
			Time: stat.up,
		})
	}
	return items
}

type SrvUI struct {
	srv  *Srv
	logs []string
	prog float64
	list list.Model
	mu   sync.Mutex
}

func NewSrvUI(srv *Srv) *SrvUI {
	items := srv.Files()
	l := list.New(items, list.NewDefaultDelegate(), 0, 0)
	l.Title = "📁 Files on Server"
	l.SetShowStatusBar(false)
	return &SrvUI{srv: srv, logs: []string{}, list: l}
}

func (s *SrvUI) Log(msg string) {
	s.mu.Lock()
	s.logs = append(s.logs, fmt.Sprintf("[%s] %s", time.Now().Format("15:04:05"), msg))
	if len(s.logs) > 8 {
		s.logs = s.logs[1:]
	}
	s.mu.Unlock()
}

func (s *SrvUI) Prog(p float64) {
	s.mu.Lock()
	s.prog = p
	s.mu.Unlock()
}

func (s *SrvUI) Init() tea.Cmd {
	return tick()
}

func (s *SrvUI) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if msg.String() == "ctrl+c" || msg.String() == "q" {
			return s, tea.Quit
		}
	case tea.WindowSizeMsg:
		s.list.SetSize(msg.Width, msg.Height-18)
	case tickMsg:
		s.list.SetItems(s.srv.Files())
		return s, tick()
	}

	var cmd tea.Cmd
	s.list, cmd = s.list.Update(msg)
	return s, cmd
}

func (s *SrvUI) View() string {
	s.mu.Lock()
	defer s.mu.Unlock()

	var b strings.Builder
	b.WriteString(titleStyle.Render("🔐 DFP Server") + "\n\n")
	b.WriteString(s.list.View() + "\n\n")

	if s.prog > 0 && s.prog < 1 {
		prog := progress.New(progress.WithDefaultGradient())
		b.WriteString(prog.ViewAs(s.prog) + "\n\n")
	}

	b.WriteString(infoStyle.Render("📋 Logs:") + "\n")
	for _, log := range s.logs {
		b.WriteString(dimStyle.Render(log) + "\n")
	}

	b.WriteString("\n" + dimStyle.Render("Press q to quit"))
	return b.String()
}

type tickMsg time.Time

func tick() tea.Cmd {
	return tea.Tick(500*time.Millisecond, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}
