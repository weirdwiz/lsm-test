package main

package main

import "C"

import (
	"os"

	"encoding/binary"
	"fmt"

	bpf "github.com/aquasecurity/libbpfgo"
)

func resizeMap(module *bpf.Module, name string, size uint32) error {
	m, err := module.GetMap("events")
	if err != nil {
		return err
	}

	if err = m.Resize(size); err != nil {
		return err
	}

	if actual := m.GetMaxEntries(); actual != size {
		return fmt.Errorf("map resize failed, expected %v, actual %v", size, actual)
	}

	return nil
}

func main() {

	bpfModule, err := bpf.NewModuleFromFile("main.bpf.o")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}
	defer bpfModule.Close()

	if err = resizeMap(bpfModule, "events", 8192); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	bpfModule.BPFLoadObject()
	prog, err := bpfModule.GetProgram("kprobe__sys_mmap")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	_, err = prog.AttachKprobe("__x64_sys_mmap")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	prog2, err := bpfModule.GetProgram("kprobe__filp")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	_, err = prog2.AttachKprobe("security_file_open")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	eventsChannel := make(chan []byte)
	rb, err := bpfModule.InitRingBuf("events", eventsChannel)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	rb.Start()

	numberOfEventsReceived := 0
	for {
		b := <-eventsChannel
		if binary.LittleEndian.Uint32(b) != 2021 {
			fmt.Fprintf(os.Stderr, "invalid data retrieved\n")
			os.Exit(-1)
		}
		numberOfEventsReceived++
		fmt.Println(numberOfEventsReceived)
	}

	// Test that it won't cause a panic or block if Stop or Close called multiple times
	rb.Stop()
	rb.Close()
}
