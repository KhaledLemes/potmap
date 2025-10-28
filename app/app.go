package application

import (
	"fmt"
	"net"
	"time"

	"github.com/urfave/cli"
)

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
			Name:   "Tq",
			Usage:  "Does a port scan of the main TCP ports",
			Flags:  flags,
			Action: tquickScan,
		},
	}

	return app
}

func tquickScan(c *cli.Context) {
	ip := c.String("ip")
	ports := []string{"20", "21", "22", "25", "53", "80", "110", "143", "443", "3389", "8080", "6969"}
	var addr string

	var scanned uint
	var open uint
	var closed uint

	for _, port := range ports {
		addr = fmt.Sprintf("%s:%s", ip, port)
		scanned++

		conn, err := net.DialTimeout("tcp", addr, time.Second*3)
		if err != nil {
			fmt.Printf("Port %s is CLOSED\n", port)
			closed++
			continue
		}
		defer conn.Close()

		fmt.Printf("Port %s is OPEN\n", port)
		open++
	}

	fmt.Println("------------------------------------------------")
	fmt.Printf("Port scan for ip %s completed.\nScanned ports: %d\nOpen ports: %d\nClosed ports: %d\n", ip, scanned, open, closed)
}
