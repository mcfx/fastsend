package main

import (
	"bufio"
	"bytes"
	"crypto/md5"
	"crypto/sha256"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"time"
)

const MaxBlockSize = 64 * 1024 * 1024

var (
	op        string
	blockSize int
	fileName  string
	fileSize  int
	port      int
	addr      string
	threads   int
	key       string
	keyb      [sha256.Size]byte
)

func parseArgs() {
	op = os.Args[1]
	commandLine := flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	commandLine.IntVar(&blockSize, "blocksize", MaxBlockSize, "Block size")
	commandLine.StringVar(&fileName, "filename", "", "File name")
	commandLine.IntVar(&fileSize, "filesize", 0, "File size")
	commandLine.IntVar(&port, "port", 0, "Port to listen")
	commandLine.StringVar(&addr, "addr", "", "Address to connect")
	commandLine.IntVar(&threads, "threads", 8, "Number of threads")
	commandLine.StringVar(&key, "key", "123456", "Key for encryption")
	commandLine.Parse(os.Args[2:])
	if fileName == "" {
		fmt.Println("invalid filename")
		os.Exit(2)
	}
	if fileSize == 0 && op == "create" {
		fmt.Println("invalid filesize")
		os.Exit(2)
	}
	if port == 0 && op == "recv" {
		fmt.Println("invalid port")
		os.Exit(2)
	}
	if addr == "" && op == "send" {
		fmt.Println("invalid addr")
		os.Exit(2)
	}
	keyb = sha256.Sum256([]byte(key))
}

func create() {
	cmd := exec.Command("fallocate", "-l", strconv.Itoa(fileSize), "-x", fileName)
	err := cmd.Run()
	if err != nil {
		fmt.Println("error when calling fallocate")
		os.Remove(fileName)
		os.Exit(3)
	}
	stat, err := os.Stat(fileName)
	if int(stat.Size()) != fileSize {
		fmt.Println("fallocate error, file size mismatch")
		os.Remove(fileName)
		os.Exit(4)
	}
}

const (
	pReq  = 1
	pData = 2
	pStop = 3
)

var (
	numBlocks     int
	lstBlockSize  int
	blockTransfer chan int
)

func prepareBlocks() {
	numBlocks = (fileSize + blockSize - 1) / blockSize
	lstBlockSize = fileSize - (numBlocks-1)*blockSize
	fmt.Printf("%d blocks in total\n", numBlocks)
	blockTransfer = make(chan int, numBlocks)
}

func encrypt(s []byte) {
	for i := 0; i < len(s); i++ {
		s[i] ^= keyb[i&(sha256.Size-1)]
	}
}

func printStats() {
	const LEN = 30
	ht := []int{}
	for {
		time.Sleep(time.Second)
		sum := 0
		for len(blockTransfer) != 0 {
			t := <-blockTransfer
			sum += t
		}
		if len(ht) < LEN {
			ht = append(ht, sum)
		} else {
			ht = append(ht[1:], sum)
		}
		sum = 0
		for i := 0; i < len(ht); i++ {
			sum += ht[i]
		}
		spd := float64(sum) / float64(len(ht)) / 1024 / 1024
		fmt.Printf("%s speed: %.2fMB/s\n", op, spd)
	}
}

func send() {
	stat, _ := os.Stat(fileName)
	fileSize = int(stat.Size())
	prepareBlocks()

	tch := make(chan bool, threads)
	stop := make(chan bool, 100)

	for i := 0; i < threads; i++ {
		tch <- true
	}

	connect := func(threadId int) {
		select {
		case <-stop:
			stop <- true
			return
		default:
		}
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			//fmt.Printf("error when connecting to %v: %v\n", addr, err)
			tch <- true
			return
		}
		fmt.Printf("%d connection established\n", threadId)
		f, err := os.Open(fileName)
		writer := bufio.NewWriter(conn)
		reader := bufio.NewReader(conn)
		opbuf := make([]byte, 1)
		idbuf := make([]byte, 8)
		for {
			n, err := io.ReadFull(reader, opbuf)
			if n != 1 || err != nil {
				fmt.Printf("failed to read packet info")
				tch <- true
				conn.Close()
				f.Close()
				return
			}
			if opbuf[0] == pStop {
				fmt.Printf("%d received stop\n", threadId)
				writer.Write(opbuf)
				writer.Flush()
				stop <- true
				f.Close()
				return
			}
			n, err = io.ReadFull(reader, idbuf)
			if n != 8 || err != nil {
				fmt.Printf("failed to read packet block id")
				tch <- true
				conn.Close()
				f.Close()
				return
			}
			blockId := int(binary.LittleEndian.Uint64(idbuf))
			//fmt.Printf("%d send block %d\n", threadId, blockId)
			sz := blockSize
			if blockId == numBlocks-1 {
				sz = lstBlockSize
			}
			data := make([]byte, sz)
			n, err = f.ReadAt(data, int64(blockId*blockSize))
			if err != nil {
				fmt.Printf("failed to read block data")
				tch <- true
				conn.Close()
				f.Close()
				return
			}
			hash := md5.Sum(data)
			encrypt(data)
			opbuf[0] = pData
			writer.Write(opbuf)
			writer.Write(idbuf)
			writer.Write(data)
			writer.Write(hash[:])
			writer.Flush()
			blockTransfer <- sz
		}
	}

	go printStats()

	cnt := 0
outer_for:
	for {
		select {
		case <-tch:
			cnt++
			go connect(cnt)
		case <-stop:
			stop <- true
			break outer_for
		}
	}
	os.Exit(0)
}

func recv() {
	ln, err := net.Listen("tcp", ":"+strconv.Itoa(port))
	if err != nil {
		fmt.Printf("error when listen: %v\n", err)
		os.Exit(3)
	}
	fmt.Printf("listening at port %v\n", port)
	stat, _ := os.Stat(fileName)
	fileSize = int(stat.Size())
	prepareBlocks()

	blocks := make(chan int, numBlocks)
	doneBlocks := make(chan struct {
		id   int
		data []byte
	}, numBlocks)
	ths := make(chan bool, 100)
	stop := make(chan bool, 100)
	stopped := make(chan bool, 100)

	flusher := func() {
		f, err := os.OpenFile(fileName, os.O_WRONLY, 0644)
		if err != nil {
			fmt.Printf("error when opening file: %v\n", err)
			os.Exit(5)
		}
		for i := 0; i < numBlocks; i++ {
			blocks <- i
		}
		for i := 0; i < numBlocks; i++ {
			block := <-doneBlocks
			f.WriteAt(block.data, int64(block.id*blockSize))
		}
		f.Close()
		cnt := 0
	outer_for:
		for {
			select {
			case <-ths:
				stop <- true
				cnt++
			default:
				break outer_for
			}
		}
		for i := 0; i < cnt; i++ {
			<-stopped
		}
		ln.Close()
	}

	handle := func(conn net.Conn, threadId int) {
		fmt.Printf("%d connection established\n", threadId)
		ths <- true
		writer := bufio.NewWriter(conn)
		reader := bufio.NewReader(conn)
		var blockId int
		buf := make([]byte, 9)
		hbuf := make([]byte, md5.Size)
		for {
			select {
			case blockId = <-blocks:
			case <-stop:
				writer.Write([]byte{pStop})
				writer.Flush()
				conn.Close()
				stopped <- true
				return
			}
			buf[0] = pReq
			binary.LittleEndian.PutUint64(buf[1:9], uint64(blockId))
			writer.Write(buf)
			writer.Flush()
			//fmt.Printf("%d req block %d\n", threadId, blockId)
			n, err := io.ReadFull(reader, buf)
			if n != 9 || err != nil {
				fmt.Printf("failed to read packet info")
				blocks <- blockId
				conn.Close()
				<-ths
				return
			}
			blkId := int(binary.LittleEndian.Uint64(buf[1:9]))
			if buf[0] != pData || blkId != blockId {
				fmt.Printf("error when receiving data: type=%v blkId=%v\n", buf[0], blkId)
				os.Exit(4)
			}
			sz := blockSize
			if blkId == numBlocks-1 {
				sz = lstBlockSize
			}
			data := make([]byte, sz)
			n, err = io.ReadFull(reader, data)
			if n != sz || err != nil {
				fmt.Printf("failed to read data")
				blocks <- blockId
				conn.Close()
				<-ths
				return
			}
			n, err = io.ReadFull(reader, hbuf)
			if n != 16 || err != nil {
				fmt.Printf("failed to read hash")
				blocks <- blockId
				conn.Close()
				<-ths
				return
			}
			encrypt(data)
			realHash := md5.Sum(data)
			if bytes.Compare(hbuf, realHash[:]) != 0 {
				fmt.Printf("hash check failed")
				blocks <- blockId
				conn.Close()
				<-ths
				return
			}
			doneBlocks <- struct {
				id   int
				data []byte
			}{id: blockId, data: data}
			blockTransfer <- sz
		}
	}

	go flusher()
	go printStats()

	cnt := 0
	for {
		conn, err := ln.Accept()
		if err != nil {
			//fmt.Printf("error when accepting connection: %v\n", err)
			break
		}
		cnt++
		go handle(conn, cnt)
	}
	os.Exit(0)
}

func main() {
	parseArgs()
	if op == "create" {
		create()
	} else if op == "send" {
		send()
	} else if op == "recv" {
		recv()
	} else {
		fmt.Printf("invalid operation %v\n", op)
	}
}
