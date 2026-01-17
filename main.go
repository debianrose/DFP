package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/charmbracelet/bubbles/filepicker"
	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/progress"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/quic-go/quic-go"
)

const (
	CHUNK      = 128 * 1024
	STORE      = "./storage"
	EXT        = ".enc"
	MaxRetries = 5
)

var (
	titleStyle  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#00FF00"))
	errorStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("#FF0000"))
	successStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#00FF00"))
	infoStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("#00FFFF"))
)

type Crypto struct {
	key []byte
}

func NewCrypto(pass string) *Crypto {
	h := sha256.Sum256([]byte(pass))
	return &Crypto{key: h[:]}
}

func (c *Crypto) Enc(data []byte) ([]byte, error) {
	blk, _ := aes.NewCipher(c.key)
	gcm, _ := cipher.NewGCM(blk)
	n := make([]byte, gcm.NonceSize())
	io.ReadFull(rand.Reader, n)
	return gcm.Seal(n, n, data, nil), nil
}

func (c *Crypto) Dec(data []byte) ([]byte, error) {
	blk, _ := aes.NewCipher(c.key)
	gcm, _ := cipher.NewGCM(blk)
	ns := gcm.NonceSize()
	if len(data) < ns {
		return nil, fmt.Errorf("invalid")
	}
	return gcm.Open(nil, data[:ns], data[ns:], nil)
}

func zip(data []byte) []byte {
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	w.Write(data)
	w.Close()
	return b.Bytes()
}

func unzip(data []byte) ([]byte, error) {
	r, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return io.ReadAll(r)
}

func genTLS() (*tls.Config, error) {
	k, _ := rsa.GenerateKey(rand.Reader, 2048)
	t := x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now(), NotAfter: time.Now().Add(365 * 24 * time.Hour)}
	cDER, _ := x509.CreateCertificate(rand.Reader, &t, &t, &k.PublicKey, k)
	kPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)})
	cPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cDER})
	cert, _ := tls.X509KeyPair(cPEM, kPEM)
	return &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"qft"}}, nil
}

func qcfg() *quic.Config {
	return &quic.Config{
		MaxIncomingStreams:             100,
		MaxIncomingUniStreams:          100,
		InitialStreamReceiveWindow:     2 * 1024 * 1024,
		MaxStreamReceiveWindow:         10 * 1024 * 1024,
		InitialConnectionReceiveWindow: 3 * 1024 * 1024,
		MaxConnectionReceiveWindow:     10 * 1024 * 1024,
		MaxIdleTimeout:                 60 * time.Second,
		KeepAlivePeriod:                20 * time.Second,
	}
}

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
	tls, _ := genTLS()
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
	l, err := quic.ListenAddr(addr, s.tls, qcfg())
	if err != nil {
		return err
	}
	defer l.Close()

	ui.Log(fmt.Sprintf("Server started on %s", addr))
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

	ui.Log(fmt.Sprintf("⬇ %s (%d bytes)", name, sz))

	buf := bytes.NewBuffer(make([]byte, 0, sz))
	var rcv uint64
	tmp := make([]byte, CHUNK)

	for rcv < sz {
		n, err := st.Read(tmp)
		if err != nil {
			return
		}
		buf.Write(tmp[:n])
		rcv += uint64(n)
		ui.Prog(float64(rcv) / float64(sz))
	}

	data := buf.Bytes()
	comp := zip(data)
	enc, _ := s.crypto.Enc(comp)

	path := filepath.Join(STORE, name+EXT)
	os.WriteFile(path, enc, 0644)

	s.scan()
	ratio := float64(len(data)) / float64(len(enc))
	ui.Log(fmt.Sprintf("✅ %s (%.2fx)", name, ratio))
	st.Write([]byte("OK"))
}

func (s *Srv) download(st quic.Stream, ui *SrvUI) {
	var nLen uint32
	binary.Read(st, binary.BigEndian, &nLen)
	nb := make([]byte, nLen)
	io.ReadFull(st, nb)
	name := string(nb)

	ui.Log(fmt.Sprintf("⬆ %s", name))

	path := filepath.Join(STORE, name+EXT)
	enc, err := os.ReadFile(path)
	if err != nil {
		binary.Write(st, binary.BigEndian, uint64(0))
		return
	}

	comp, _ := s.crypto.Dec(enc)
	data, _ := unzip(comp)

	binary.Write(st, binary.BigEndian, uint64(len(data)))

	var sent uint64
	for sent < uint64(len(data)) {
		end := sent + CHUNK
		if end > uint64(len(data)) {
			end = uint64(len(data))
		}
		st.Write(data[sent:end])
		sent = end
		ui.Prog(float64(sent) / float64(len(data)))
	}

	ui.Log(fmt.Sprintf("✅ %s", name))
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
			name: f,
			size: stat.size,
			time: stat.up,
		})
	}
	return items
}

type Cli struct {
	tls *tls.Config
}

func NewCli() *Cli {
	return &Cli{
		tls: &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"qft"}},
	}
}

func (c *Cli) Upload(addr, local, remote string, onProg func(float64)) error {
	data, err := os.ReadFile(local)
	if err != nil {
		return err
	}

	var conn quic.Connection
	for i := 0; i < MaxRetries; i++ {
		conn, err = quic.DialAddr(context.Background(), addr, c.tls, qcfg())
		if err == nil {
			break
		}
		time.Sleep(time.Second * time.Duration(i+1))
	}
	if err != nil {
		return err
	}
	defer conn.CloseWithError(0, "")

	st, _ := conn.OpenStreamSync(context.Background())
	defer st.Close()

	st.Write([]byte{0})
	binary.Write(st, binary.BigEndian, uint32(len(remote)))
	st.Write([]byte(remote))
	binary.Write(st, binary.BigEndian, uint64(len(data)))

	var sent uint64
	for sent < uint64(len(data)) {
		end := sent + CHUNK
		if end > uint64(len(data)) {
			end = uint64(len(data))
		}
		st.Write(data[sent:end])
		sent = end
		if onProg != nil {
			onProg(float64(sent) / float64(len(data)))
		}
	}

	ack := make([]byte, 2)
	st.Read(ack)
	return nil
}

func (c *Cli) Download(addr, remote, local string, onProg func(float64)) error {
	var conn quic.Connection
	var err error
	for i := 0; i < MaxRetries; i++ {
		conn, err = quic.DialAddr(context.Background(), addr, c.tls, qcfg())
		if err == nil {
			break
		}
		time.Sleep(time.Second * time.Duration(i+1))
	}
	if err != nil {
		return err
	}
	defer conn.CloseWithError(0, "")

	st, _ := conn.OpenStreamSync(context.Background())
	defer st.Close()

	st.Write([]byte{1})
	binary.Write(st, binary.BigEndian, uint32(len(remote)))
	st.Write([]byte(remote))

	var sz uint64
	binary.Read(st, binary.BigEndian, &sz)
	if sz == 0 {
		return fmt.Errorf("not found")
	}

	buf := bytes.NewBuffer(make([]byte, 0, sz))
	var rcv uint64
	tmp := make([]byte, CHUNK)

	for rcv < sz {
		n, err := st.Read(tmp)
		if err != nil {
			break
		}
		buf.Write(tmp[:n])
		rcv += uint64(n)
		if onProg != nil {
			onProg(float64(rcv) / float64(sz))
		}
	}

	return os.WriteFile(local, buf.Bytes(), 0644)
}

func (c *Cli) List(addr string) ([]FileItem, error) {
	conn, err := quic.DialAddr(context.Background(), addr, c.tls, qcfg())
	if err != nil {
		return nil, err
	}
	defer conn.CloseWithError(0, "")

	st, _ := conn.OpenStreamSync(context.Background())
	defer st.Close()

	st.Write([]byte{2})

	var cnt uint32
	binary.Read(st, binary.BigEndian, &cnt)

	items := []FileItem{}
	for i := uint32(0); i < cnt; i++ {
		var nLen uint32
		binary.Read(st, binary.BigEndian, &nLen)
		nb := make([]byte, nLen)
		io.ReadFull(st, nb)

		var sz uint64
		binary.Read(st, binary.BigEndian, &sz)

		items = append(items, FileItem{
			name: string(nb),
			size: int64(sz),
		})
	}

	return items, nil
}

type FileItem struct {
	name string
	size int64
	time time.Time
}

func (f FileItem) Title() string       { return f.name }
func (f FileItem) Description() string { return fmt.Sprintf("%d bytes", f.size) }
func (f FileItem) FilterValue() string { return f.name }

type SrvUI struct {
	srv    *Srv
	logs   []string
	prog   float64
	list   list.Model
	mu     sync.Mutex
}

func NewSrvUI(srv *Srv) *SrvUI {
	items := srv.Files()
	l := list.New(items, list.NewDefaultDelegate(), 0, 0)
	l.Title = "Files on Server"
	return &SrvUI{srv: srv, logs: []string{}, list: l}
}

func (s *SrvUI) Log(msg string) {
	s.mu.Lock()
	s.logs = append(s.logs, fmt.Sprintf("[%s] %s", time.Now().Format("15:04:05"), msg))
	if len(s.logs) > 10 {
		s.logs = s.logs[1:]
	}
	s.mu.Unlock()
}

func (s *SrvUI) Prog(p float64) {
	s.mu.Lock()
	s.prog = p
	s.mu.Unlock()
}

func (s *SrvUI) Init() tea.Cmd { return nil }

func (s *SrvUI) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if msg.String() == "ctrl+c" || msg.String() == "q" {
			return s, tea.Quit
		}
	case tea.WindowSizeMsg:
		s.list.SetSize(msg.Width, msg.Height-15)
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
	b.WriteString(titleStyle.Render("DFP Server") + "\n\n")
	
	b.WriteString(infoStyle.Render("Files:") + "\n")
	b.WriteString(s.list.View() + "\n\n")

	if s.prog > 0 {
		prog := progress.New(progress.WithDefaultGradient())
		b.WriteString(prog.ViewAs(s.prog) + "\n\n")
	}

	b.WriteString(infoStyle.Render("Logs:") + "\n")
	for _, log := range s.logs {
		b.WriteString(log + "\n")
	}

	b.WriteString("\n" + infoStyle.Render("Press q to quit"))
	return b.String()
}

type tickMsg time.Time

func tick() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

type CliUI struct {
	state    int
	addr     textinput.Model
	picker   filepicker.Model
	list     list.Model
	prog     progress.Model
	progress float64
	err      string
	msg      string
	cli      *Cli
	files    []FileItem
	selFile  string
}

func NewCliUI() *CliUI {
	addr := textinput.New()
	addr.Placeholder = "127.0.0.1:5000"
	addr.Focus()

	picker := filepicker.New()
	picker.CurrentDirectory, _ = os.UserHomeDir()

	prog := progress.New(progress.WithDefaultGradient())

	return &CliUI{
		state:  0,
		addr:   addr,
		picker: picker,
		prog:   prog,
		cli:    NewCli(),
	}
}

func (c *CliUI) Init() tea.Cmd {
	return textinput.Blink
}

func (c *CliUI) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q":
			return c, tea.Quit
		case "enter":
			if c.state == 0 && c.addr.Value() != "" {
				c.state = 1
				return c, c.picker.Init()
			}
		}
	case progressMsg:
		c.progress = float64(msg)
		if c.progress >= 1.0 {
			c.state = 3
			c.msg = "✅ Upload complete!"
		}
		return c, nil
	case errMsg:
		c.err = string(msg)
		c.state = 3
		return c, nil
	}

	switch c.state {
	case 0:
		var cmd tea.Cmd
		c.addr, cmd = c.addr.Update(msg)
		return c, cmd
	case 1:
		var cmd tea.Cmd
		c.picker, cmd = c.picker.Update(msg)
		
		if didSelect, path := c.picker.DidSelectFile(msg); didSelect {
			c.selFile = path
			c.state = 2
			return c, c.doUpload()
		}
		return c, cmd
	}

	return c, nil
}

func (c *CliUI) View() string {
	var b strings.Builder
	b.WriteString(titleStyle.Render("DFP Client") + "\n\n")

	switch c.state {
	case 0:
		b.WriteString("Server address:\n")
		b.WriteString(c.addr.View() + "\n\n")
		b.WriteString(infoStyle.Render("Press Enter to continue"))
	case 1:
		b.WriteString("Select file to upload:\n")
		b.WriteString(c.picker.View())
	case 2:
		b.WriteString(fmt.Sprintf("Uploading: %s\n\n", filepath.Base(c.selFile)))
		b.WriteString(c.prog.ViewAs(c.progress))
	case 3:
		if c.err != "" {
			b.WriteString(errorStyle.Render("Error: " + c.err))
		} else {
			b.WriteString(successStyle.Render(c.msg))
		}
		b.WriteString("\n\n" + infoStyle.Render("Press q to quit"))
	}

	return b.String()
}

type progressMsg float64
type errMsg string

func (c *CliUI) doUpload() tea.Cmd {
	return func() tea.Msg {
		name := filepath.Base(c.selFile)
		err := c.cli.Upload(c.addr.Value(), c.selFile, name, func(p float64) {
			c.progress = p
		})
		if err != nil {
			return errMsg(err.Error())
		}
		return progressMsg(1.0)
	}
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: qft <server|client>")
		os.Exit(1)
	}

	switch os.Args[1] {
	case "server":
		pass := "secret"
		if len(os.Args) > 2 {
			pass = os.Args[2]
		}

		srv, _ := NewSrv(5000, pass)
		ui := NewSrvUI(srv)

		go srv.Run(ui)

		p := tea.NewProgram(ui)
		p.Run()

	case "client":
		p := tea.NewProgram(NewCliUI())
		p.Run()
	}
}
