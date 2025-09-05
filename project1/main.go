package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"strconv"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

const bpfObjPath = "./drop_tcp.o"
const defaultPort = uint16(4040)

func main() {
	var port uint16
	if len(os.Args) > 1 {
		p, err := strconv.Atoi(os.Args[1])
		if err != nil || p <= 0 || p > 65535 {
			log.Fatalf("invalid port number: %v", os.Args[1])
		}
		port = uint16(p)
	} else {
		port = defaultPort
	}
	fmt.Printf("Blocking TCP port: %d\n", port)

	spec, err := ebpf.LoadCollectionSpec(bpfObjPath)
	if err != nil {
		log.Fatalf("loading collection spec: %v", err)
	}

	objs := struct {
		DropTcpPort *ebpf.Program `ebpf:"drop_tcp_port"`
		BlockedPort *ebpf.Map     `ebpf:"blocked_port"`
	}{}

	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.DropTcpPort.Close()
	defer objs.BlockedPort.Close()

	key := uint32(0)
	if err := objs.BlockedPort.Put(key, port); err != nil {
		log.Fatalf("failed to set blocked port: %v", err)
	}

	cgroupPath := "/sys/fs/cgroup"
	cgroupFD, err := os.Open(cgroupPath)
	if err != nil {
		log.Fatalf("failed to open cgroup path: %v", err)
	}
	defer cgroupFD.Close()

	l, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  ebpf.AttachCGroupInetIngress,
		Program: objs.DropTcpPort,
	})
	if err != nil {
		log.Fatalf("failed to attach program: %v", err)
	}
	defer l.Close()

	fmt.Println("eBPF program attached.")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
}
