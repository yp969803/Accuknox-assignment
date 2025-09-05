package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

const bpfObjPath = "./drop_tcp.o"

func main() {
	fmt.Println("Dropping all TCP traffic except for port 4040 for process 'myprocess'")

	spec, err := ebpf.LoadCollectionSpec(bpfObjPath)
	if err != nil {
		log.Fatalf("loading collection spec: %v", err)
	}

	objs := struct {
		AllowTcpForProcess *ebpf.Program `ebpf:"allow_tcp_for_process"`
	}{}

	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.AllowTcpForProcess.Close()

	cgroupPath := "/sys/fs/cgroup"
	l, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  ebpf.AttachCGroupInet4Connect, 
		Program: objs.AllowTcpForProcess,
	})
	if err != nil {
		log.Fatalf("failed to attach program: %v", err)
	}
	defer l.Close()

	fmt.Println("eBPF program attached. Press Ctrl+C to exit.")
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
}
