package main

import (
	"C"
	"os"
	"os/signal"

	bpf "github.com/aquasecurity/libbpfgo"
)

func main() {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)

	bpfModule, err := bpf.NewModuleFromFile("hello.bpf.o")
	must(err)
	defer bpfModule.Close()

	err = bpfModule.BPFLoadObject()
	must(err)

	prog, err := bpfModule.GetProgram("hello")
	must(err)
	_, err = prog.AttachKprobe("sys_execve")
	must(err)
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
