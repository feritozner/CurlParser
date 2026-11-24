// Command curlp is a small HTTP request workbench in the spirit of Burp Repeater.
//
//	go run ./cmd/curlp            (or: go run cmd/curlp/main.go)
//	go build -o bin/curlp ./cmd/curlp
package main

import (
	"flag"
	"fmt"
	"net/http"
	"os/exec"
	"runtime"
	"time"

	"curlp/internal/server"
	"curlp/web"
)

func openBrowser(u string) {
	switch runtime.GOOS {
	case "windows":
		exec.Command("rundll32", "url.dll,FileProtocolHandler", u).Start()
	case "darwin":
		exec.Command("open", u).Start()
	default:
		exec.Command("xdg-open", u).Start()
	}
}

func main() {
	port := flag.String("port", "9002", "port to listen on (127.0.0.1 only)")
	noOpen := flag.Bool("no-open", false, "do not open the browser automatically")
	flag.Parse()

	addr := "127.0.0.1:" + *port
	srv := server.New(*port, web.Static())

	fmt.Println("curlp is running at http://" + addr + "  (Ctrl+C to quit)")
	if !*noOpen {
		go func() { time.Sleep(300 * time.Millisecond); openBrowser("http://" + addr) }()
	}
	if err := http.ListenAndServe(addr, srv.Handler()); err != nil {
		fmt.Println("server stopped:", err)
	}
}
