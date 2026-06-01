package main

import (
	"flag"
	"fmt"
	"log"
	"net"
)
import (
	"encoding/binary"
	"errors"
	"io"
	"os"
	"sync"
)

var authRequired bool
var proxyUser string
var proxyPass string

func main() {
	port := flag.Int("port", 1080, "port to listen on")
	flag.Parse()

	proxyUser = os.Getenv("PROXY_USER")
	proxyPass = os.Getenv("PROXY_PASS")
	authRequired = proxyUser != ""

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		log.Fatalf("failed to listen on port %d: %v", *port, err)
	}
	defer listener.Close()

	log.Printf("SOCKS5 proxy listening on :%d", *port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("accept error: %v", err)
			continue
		}
		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()

	// TODO: Implement SOCKS5 protocol
	// 1. Read client greeting and negotiate authentication method
	err := methodNegotiation(conn)
	if err != nil {
		return
	}
	// 2. Perform authentication if required (when PROXY_USER env var is set)
	if authRequired {
		err = authenticate(conn)
		if err != nil {
			return
		}
	}
	// 3. Read CONNECT request and Dial target server
	targetConn, err := handleConnectRequest(conn)
	if err != nil {
		return
	}
	defer targetConn.Close()

	// 6. Relay data between client and target
	relay(conn, targetConn)
}
func methodNegotiation(conn net.Conn) error {
	verBuf := make([]byte, 1)
	_, err := io.ReadFull(conn, verBuf)
	if err != nil {
		err = errors.New("failed to read SOCKS version")
		return err
	}
	if verBuf[0] != 0x05 {
		err = errors.New("unsupported SOCKS version")
		return err
	}
	nMethodsBuf := make([]byte, 1)
	_, err = io.ReadFull(conn, nMethodsBuf)
	if err != nil {
		err = errors.New("failed to read number of authentication methods")
		return err
	}
	nMethods := int(nMethodsBuf[0])

	methodsBuf := make([]byte, nMethods)
	_, err = io.ReadFull(conn, methodsBuf)
	if err != nil {
		err = errors.New("failed to read authentication methods")
		return err
	}

	if authRequired {
		included := false
		for _, method := range methodsBuf {
			if method == 0x02 {
				included = true
				break
			}
		}
		if !included {
			log.Print("username/password authentication not supported")
			conn.Write([]byte{0x05, 0xFF})
			err = errors.New("username/password authentication not supported")
			return err
		}
		conn.Write([]byte{0x05, 0x02})
		return nil
	} else {
		for _, method := range methodsBuf {
			if method == 0x00 {
				conn.Write([]byte{0x05, 0x00})
				return nil
			}
		}
		conn.Write([]byte{0x05, 0xFF})
		err = errors.New("no supported authentication methods")
		return err
		
	}
}

func authenticate(conn net.Conn) error {
	authVerBuf := make([]byte, 1)
	_, err := io.ReadFull(conn, authVerBuf)
	if err != nil {
		conn.Write([]byte{0x01, 0x01})
		return err
	}
	if authVerBuf[0] != 0x01 {
		conn.Write([]byte{0x01, 0x01})
		return errors.New("unsupported authentication version")
	}

	ulenBuf := make([]byte, 1)
	_, err = io.ReadFull(conn, ulenBuf)
	if err != nil {
		conn.Write([]byte{0x01, 0x01})
		return err
	}

	ulen := int(ulenBuf[0])
	unameBuf := make([]byte, ulen)
	_, err = io.ReadFull(conn, unameBuf)
	if err != nil {
		conn.Write([]byte{0x01, 0x01})
		return err
	}

	plenBuf := make([]byte, 1)
	_, err = io.ReadFull(conn, plenBuf)
	if err != nil {
		conn.Write([]byte{0x01, 0x01})
		return err
	}

	plen := int(plenBuf[0])
	passwdBuf := make([]byte, plen)
	_, err = io.ReadFull(conn, passwdBuf)
	if err != nil {
		conn.Write([]byte{0x01, 0x01})
		return err
	}

	if string(unameBuf) == proxyUser && string(passwdBuf) == proxyPass {
		conn.Write([]byte{0x01, 0x00})
		return nil
	} else {
		conn.Write([]byte{0x01, 0x01})
		return errors.New("invalid username or password")
	}
}
func handleConnectRequest(conn net.Conn) (net.Conn, error) {
	verBuf := make([]byte, 1)
	_, err := io.ReadFull(conn, verBuf)
	if err != nil {
		return nil, errors.New("failed to read SOCKS version")
	}
	if verBuf[0] != 0x05 {
		return nil, errors.New("unsupported SOCKS version")
	}

	cmdBuf := make([]byte, 1)
	_, err = io.ReadFull(conn, cmdBuf)
	if err != nil {
		return nil, errors.New("failed to read command")
	}
	if cmdBuf[0] != 0x01 {
		sendConnectReply(conn, 0x07)
		return nil, errors.New("unsupported command")
	}

	rsvBuf := make([]byte, 1)
	_, err = io.ReadFull(conn, rsvBuf)
	if err != nil {
		return nil, errors.New("failed to read reserved field")
	}
	if rsvBuf[0] != 0x00 {
		return nil, errors.New("invalid reserved field")
	}

	atypBuf := make([]byte, 1)
	_, err = io.ReadFull(conn, atypBuf)
	if err != nil {
		return nil, errors.New("failed to read address type")
	}

	var dstAddrBuf []byte
	if atypBuf[0] == 0x01 {
		dstAddrBuf = make([]byte, 4)
		_, err = io.ReadFull(conn, dstAddrBuf)
		if err != nil {
			return nil, errors.New("failed to read IPv4 address")
		}
	} else if atypBuf[0] == 0x03 {
		domainLenBuf := make([]byte, 1)
		_, err = io.ReadFull(conn, domainLenBuf)
		if err != nil {
			return nil, errors.New("failed to read domain length")
		}
		domainLen := int(domainLenBuf[0])

		dstAddrBuf = make([]byte, domainLen)
		_, err = io.ReadFull(conn, dstAddrBuf)
		if err != nil {
			return nil, errors.New("failed to read domain")
		}
	} else {
		sendConnectReply(conn, 0x08)
		return nil, errors.New("unsupported address type")
	}

	portBuf := make([]byte, 2)
	_, err = io.ReadFull(conn, portBuf)
	if err != nil {
		return nil, errors.New("failed to read port")
	}
	port := binary.BigEndian.Uint16(portBuf)

	var dstAddr string
	if atypBuf[0] == 0x01 {
		dstAddr = net.IP(dstAddrBuf).String()
	} else {
		dstAddr = string(dstAddrBuf)
	}

	target := fmt.Sprintf("%s:%d", dstAddr, port)
	targetConn, err := net.Dial("tcp", target)
	if err != nil {
		sendConnectReply(conn, 0x05)
		return nil, err
	}
	sendConnectReply(conn, 0x00)
	return targetConn, nil
}

func sendConnectReply(conn net.Conn, rep byte) {
	conn.Write([]byte{0x05, rep, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
}

func relay(clientConn net.Conn, targetConn net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		io.Copy(targetConn, clientConn)
		targetConn.(*net.TCPConn).CloseWrite()
	}()
	go func() {
		defer wg.Done()
		io.Copy(clientConn, targetConn)
		clientConn.(*net.TCPConn).CloseWrite()
	}()
	wg.Wait()
}
