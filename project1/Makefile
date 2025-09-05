all: makeEbpf makeGo

makeEbpf:
	clang -O2 -g -target bpf -c drop_tcp.c -o drop_tcp.o

makeGo:
	go build -o loader main.go

run: all
	sudo ./loader
