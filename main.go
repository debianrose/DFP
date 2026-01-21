package main

import (
	"fmt"
	"os"

	tea "github.com/charmbracelet/bubbletea"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: qft <server|client>")
		fmt.Println("\nServer: qft server [password]")
		fmt.Println("Client: qft client")
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

	default:
		fmt.Println("Unknown command. Use 'server' or 'client'")
		os.Exit(1)
	}
}
