package application

import (
	"errors"
	"fmt"
	"log"
	"net"
	"strconv"
	"time"

	"github.com/urfave/cli"
)

type scanResult struct {
	ip    string
	ports []string
	addr  string

	scanned  uint
	open     uint
	closed   uint
	filtered uint
}

var result = scanResult{}

func Generate() *cli.App {
	app := cli.NewApp()
	app.Name = "potmap"
	app.Usage = "A simple port scanner created by a simple student"

	flags := []cli.Flag{
		// Ip is the one that will be scanned
		cli.StringFlag{
			Name:  "ip",
			Value: "127.0.0.1",
		},
	}

	app.Commands = []cli.Command{
		{
			Name:   "tq",
			Usage:  "Does a port scan of the main TCP ports",
			Flags:  flags,
			Action: tQuickScan,
		},
		{
			Name:   "uq",
			Usage:  "Does a port scan of the main UDP ports",
			Flags:  flags,
			Action: uQuickScan,
		},
	}

	return app
}

func tQuickScan(c *cli.Context) {
	result.ip = c.String("ip")
	result.ports = []string{"20", "21", "22", "25", "53", "80", "110", "143", "443", "3389", "8080"}

	result.scanned = uint(len(result.ports))

	for _, port := range result.ports {
		result.addr = fmt.Sprintf("%s:%s", result.ip, port)

		conn, err := net.DialTimeout("tcp", result.addr, time.Second*3)
		// Will check whether a connection is closed or filtered
		if err != nil {
			var nerr net.Error
			if errors.As(err, &nerr) && nerr.Timeout() {
				fmt.Printf("Port %s is FILTERED\n", port)
				result.filtered++
				continue
			}

			fmt.Printf("Port %s is CLOSED\n", port)
			result.closed++
			continue
		}

		fmt.Printf("Port %s is OPEN\n", port)
		result.open++

		conn.Close()
	}

	fmt.Println("------------------------------------------------")
	fmt.Printf("Port scan for ip %s completed.\nScanned ports: %d\nOpen ports: %d\nFiltered ports: %d\nClosed ports: %d\n", result.ip, result.scanned, result.open, result.filtered, result.closed)
}

func uQuickScan(c *cli.Context) {
	result.ip = c.String("ip")
	result.ports = []string{"53", "67", "68", "69", "123", "161", "162", "500", "4500"}

	result.scanned = uint(len(result.ports))

	PacketConn, err := net.ListenPacket("udp", ":0")
	if err != nil {
		fmt.Println("The program failed to open a generic UDP connection.")
		log.Fatal(err)
	}
	defer PacketConn.Close()

	for _, port := range result.ports {
		cport, err := strconv.ParseInt(port, 10, 16)
		if err != nil {
			fmt.Println("There was an error converting port to uint.")
			log.Fatal(err)
		}

		// This part of the code writes to a destiny
		dest := &net.UDPAddr{IP: net.ParseIP(result.ip), Port: int(cport)}
		payload := []byte("WHOAREYOU")
		_, err = PacketConn.WriteTo(payload, dest)

		// Creates buffer
		buffer := make([]byte, 4096)

		// To avoid too much requests, the number of attempts is limited
		const attempts = 3
		for attempt := 1; attempt <= attempts; attempt++ {

			// This part reads the response with a timeout
			PacketConn.SetReadDeadline(time.Now().Add(2 * time.Second)) //Sets the timeout to 2 seconds from now

			n, _, err := PacketConn.ReadFrom(buffer)
			if err != nil {
				var nerr net.Error
				if errors.As(err, &nerr) && nerr.Timeout() {
					if attempt < attempts {
						time.Sleep(200 * time.Millisecond)
						continue
					}
				}
			}

		}
	}
}
