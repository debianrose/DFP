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
	"time"

	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/progress"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/quic-go/quic-go"
)

var (
	errorStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#FF0000"))
)

type Cli struct {
	tls *tls.Config
}

func NewCli() *Cli {
	return &Cli{
		tls: &tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{"qft"},
		},
	}
}

func (c *Cli) Upload(addr, local, remote string, onProg func(float64)) error {
	data, err := os.ReadFile(local)
	if err != nil {
		return err
	}

	var conn quic.Connection
	for i := 0; i < MaxRetries; i++ {
		conn, err = quic.DialAddr(context.Background(), addr, c.tls, QCfg())
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
		n, err := st.Write(data[sent:end])
		if err != nil {
			return err
		}
		sent += uint64(n)
		if onProg != nil {
			onProg(float64(sent) / float64(len(data)))
		}
	}

	ack := make([]byte, 2)
	n, err := io.ReadFull(st, ack)
	if err != nil && err != io.EOF {
		return err
	}
	if n >= 2 && string(ack[:2]) != "OK" {
		return fmt.Errorf("server error")
	}
	return nil
}

func (c *Cli) Download(addr, remote, local string, onProg func(float64)) error {
	var conn quic.Connection
	var err error
	for i := 0; i < MaxRetries; i++ {
		conn, err = quic.DialAddr(context.Background(), addr, c.tls, QCfg())
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
	if err := binary.Read(st, binary.BigEndian, &sz); err != nil {
		return err
	}
	if sz == 0 {
		return fmt.Errorf("not found")
	}

	buf := bytes.NewBuffer(make([]byte, 0, sz))
	var rcv uint64
	tmp := make([]byte, CHUNK)

	for rcv < sz {
		n, err := st.Read(tmp)
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
		if n == 0 {
			break
		}
		buf.Write(tmp[:n])
		rcv += uint64(n)
		if onProg != nil {
			onProg(float64(rcv) / float64(sz))
		}
	}

	if uint64(buf.Len()) != sz {
		return fmt.Errorf("incomplete download: got %d, expected %d", buf.Len(), sz)
	}

	return os.WriteFile(local, buf.Bytes(), 0644)
}

func (c *Cli) List(addr string) ([]FileItem, error) {
	conn, err := quic.DialAddr(context.Background(), addr, c.tls, QCfg())
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
			Name: string(nb),
			Size: int64(sz),
		})
	}

	return items, nil
}

type CliUI struct {
	state      int
	action     int
	addr       textinput.Model
	browser    *FileBrowser
	remoteList list.Model
	prog       progress.Model
	progress   float64
	err        string
	msg        string
	cli        *Cli
	selFile    string
	remoteFile string
}

type FileBrowser struct {
	cwd    string
	items  []BrowserItem
	cursor int
}

type BrowserItem struct {
	name  string
	isDir bool
	size  int64
}

func NewFileBrowser() *FileBrowser {
	cwd, _ := os.Getwd()
	fb := &FileBrowser{cwd: cwd}
	fb.scan()
	return fb
}

func (fb *FileBrowser) scan() {
	entries, _ := os.ReadDir(fb.cwd)
	fb.items = []BrowserItem{{name: "..", isDir: true}}
	
	for _, e := range entries {
		info, _ := e.Info()
		fb.items = append(fb.items, BrowserItem{
			name:  e.Name(),
			isDir: e.IsDir(),
			size:  info.Size(),
		})
	}
	
	if fb.cursor >= len(fb.items) {
		fb.cursor = len(fb.items) - 1
	}
}

func (fb *FileBrowser) Up() {
	if fb.cursor > 0 {
		fb.cursor--
	}
}

func (fb *FileBrowser) Down() {
	if fb.cursor < len(fb.items)-1 {
		fb.cursor++
	}
}

func (fb *FileBrowser) Select() (string, bool) {
	if fb.cursor >= len(fb.items) {
		return "", false
	}
	
	item := fb.items[fb.cursor]
	
	if item.isDir {
		if item.name == ".." {
			fb.cwd = filepath.Dir(fb.cwd)
		} else {
			fb.cwd = filepath.Join(fb.cwd, item.name)
		}
		fb.cursor = 0
		fb.scan()
		return "", false
	}
	
	return filepath.Join(fb.cwd, item.name), true
}

func (fb *FileBrowser) View() string {
	var b strings.Builder
	b.WriteString(infoStyle.Render(fmt.Sprintf("📂 %s", fb.cwd)) + "\n\n")
	
	start := 0
	end := len(fb.items)
	if end > 15 {
		if fb.cursor > 7 {
			start = fb.cursor - 7
		}
		end = start + 15
		if end > len(fb.items) {
			end = len(fb.items)
			start = end - 15
			if start < 0 {
				start = 0
			}
		}
	}
	
	for i := start; i < end; i++ {
		item := fb.items[i]
		icon := "📄"
		if item.isDir {
			icon = "📁"
		}
		
		line := fmt.Sprintf("%s %s", icon, item.name)
		if !item.isDir && item.size > 0 {
			line += fmt.Sprintf(" (%d bytes)", item.size)
		}
		
		if i == fb.cursor {
			b.WriteString(successStyle.Render("> " + line) + "\n")
		} else {
			b.WriteString(dimStyle.Render("  " + line) + "\n")
		}
	}
	
	return b.String()
}

func NewCliUI() *CliUI {
	addr := textinput.New()
	addr.Placeholder = "127.0.0.1:5000"
	addr.Focus()

	prog := progress.New(progress.WithDefaultGradient())
	
	l := list.New([]list.Item{}, list.NewDefaultDelegate(), 0, 0)
	l.Title = "Files on Server"
	l.SetShowStatusBar(false)

	return &CliUI{
		state:      0,
		action:     0,
		addr:       addr,
		browser:    NewFileBrowser(),
		remoteList: l,
		prog:       prog,
		cli:        NewCli(),
	}
}

func (c *CliUI) Init() tea.Cmd {
	return textinput.Blink
}

func (c *CliUI) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c":
			return c, tea.Quit
		case "q":
			if c.state == 5 {
				return c, tea.Quit
			}
		case "enter":
			if c.state == 0 && c.addr.Value() != "" {
				c.state = 1
				return c, nil
			} else if c.state == 1 {
				c.action = 0
				if msg.String() == "enter" {
					c.state = 2
					return c, nil
				}
			} else if c.state == 2 {
				if path, isFile := c.browser.Select(); isFile {
					c.selFile = path
					c.state = 3
					return c, tea.Batch(c.doUpload(), updateProgress())
				}
			} else if c.state == 4 {
				i, ok := c.remoteList.SelectedItem().(FileItem)
				if ok {
					c.remoteFile = i.Name
					c.state = 3
					return c, tea.Batch(c.doDownload(), updateProgress())
				}
			}
		case "esc":
			if c.state == 2 || c.state == 4 {
				c.state = 1
				return c, nil
			} else if c.state == 1 {
				c.state = 0
				return c, nil
			}
		case "u":
			if c.state == 1 {
				c.action = 0
				c.state = 2
				return c, nil
			}
		case "d":
			if c.state == 1 {
				c.action = 1
				c.state = 4
				return c, c.loadRemoteFiles()
			}
		case "up", "k":
			if c.state == 2 {
				c.browser.Up()
			} else if c.state == 4 {
				var cmd tea.Cmd
				c.remoteList, cmd = c.remoteList.Update(msg)
				return c, cmd
			}
		case "down", "j":
			if c.state == 2 {
				c.browser.Down()
			} else if c.state == 4 {
				var cmd tea.Cmd
				c.remoteList, cmd = c.remoteList.Update(msg)
				return c, cmd
			}
		}
	case progressMsg:
		c.progress = float64(msg)
		if c.progress >= 1.0 {
			c.state = 5
			if c.action == 0 {
				c.msg = "✅ Upload complete!"
			} else {
				c.msg = "✅ Download complete!"
			}
		}
		return c, updateProgress()
	case errMsg:
		c.err = string(msg)
		c.state = 5
		return c, nil
	case updateMsg:
		if c.state == 3 {
			return c, updateProgress()
		}
	case filesMsg:
		items := make([]list.Item, len(msg))
		for i, f := range msg {
			items[i] = f
		}
		c.remoteList.SetItems(items)
		return c, nil
	case tea.WindowSizeMsg:
		c.remoteList.SetSize(msg.Width, msg.Height-10)
	}

	switch c.state {
	case 0:
		var cmd tea.Cmd
		c.addr, cmd = c.addr.Update(msg)
		return c, cmd
	case 4:
		var cmd tea.Cmd
		c.remoteList, cmd = c.remoteList.Update(msg)
		return c, cmd
	}

	return c, nil
}

func (c *CliUI) View() string {
	var b strings.Builder
	b.WriteString(titleStyle.Render("🚀 QUIC Client") + "\n\n")

	switch c.state {
	case 0:
		b.WriteString("Server address:\n")
		b.WriteString(c.addr.View() + "\n\n")
		b.WriteString(dimStyle.Render("Press Enter to continue"))
	case 1:
		b.WriteString("Choose action:\n\n")
		b.WriteString(successStyle.Render("  [U] Upload file to server") + "\n")
		b.WriteString(successStyle.Render("  [D] Download file from server") + "\n\n")
		b.WriteString(dimStyle.Render("Press U or D | Esc: back"))
	case 2:
		b.WriteString("Select file to upload:\n\n")
		b.WriteString(c.browser.View() + "\n")
		b.WriteString(dimStyle.Render("↑/↓ or j/k: navigate | Enter: select | Esc: back"))
	case 3:
		if c.action == 0 {
			b.WriteString(fmt.Sprintf("Uploading: %s\n\n", filepath.Base(c.selFile)))
		} else {
			b.WriteString(fmt.Sprintf("Downloading: %s\n\n", c.remoteFile))
		}
		b.WriteString(c.prog.ViewAs(c.progress) + "\n\n")
		b.WriteString(infoStyle.Render(fmt.Sprintf("%.1f%%", c.progress*100)))
	case 4:
		b.WriteString("Select file to download:\n\n")
		b.WriteString(c.remoteList.View() + "\n\n")
		b.WriteString(dimStyle.Render("↑/↓: navigate | Enter: select | Esc: back"))
	case 5:
		if c.err != "" {
			b.WriteString(errorStyle.Render("❌ Error: " + c.err))
		} else {
			b.WriteString(successStyle.Render(c.msg))
		}
		b.WriteString("\n\n" + dimStyle.Render("Press q to quit"))
	}

	return b.String()
}

type progressMsg float64
type errMsg string
type updateMsg time.Time
type filesMsg []FileItem

func updateProgress() tea.Cmd {
	return tea.Tick(100*time.Millisecond, func(t time.Time) tea.Msg {
		return updateMsg(t)
	})
}

func (c *CliUI) loadRemoteFiles() tea.Cmd {
	return func() tea.Msg {
		files, err := c.cli.List(c.addr.Value())
		if err != nil {
			return errMsg(err.Error())
		}
		return filesMsg(files)
	}
}

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

func (c *CliUI) doDownload() tea.Cmd {
	return func() tea.Msg {
		savePath := filepath.Join("downloads", c.remoteFile)
		os.MkdirAll("downloads", 0755)
		
		err := c.cli.Download(c.addr.Value(), c.remoteFile, savePath, func(p float64) {
			c.progress = p
		})
		if err != nil {
			return errMsg(err.Error())
		}
		return progressMsg(1.0)
	}
}
