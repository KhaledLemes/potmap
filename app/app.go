package application

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/urfave/cli/v2"
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
	flags := []cli.Flag{
		// Ip is the one that will be scanned. If no ip is declared, localhost will be scanned.
		&cli.StringFlag{
			Name:    "ip",
			Aliases: []string{"Ip", "iP", "IP", "i"},
			Value:   "127.0.0.1",
		},
		// Ports are the ports that will be scanned. If no port is declared, the most used TCP ports will be the ones scanned
		&cli.StringSliceFlag{
			Name:    "ports",
			Aliases: []string{"p"},
			Value:   cli.NewStringSlice("20", "21", "22", "25", "53", "80", "110", "143", "443", "3389", "8080"),
		},
		&cli.BoolFlag{
			Name:    "ShowClosed",
			Aliases: []string{"all", "seeall", "c", "sc", "showclosed", "show-closed"},
			Value:   false,
		},
	}

	app := cli.App{
		Name:  "potmap",
		Usage: "A simple port scanner created by a simple student",
		Commands: []*cli.Command{
			&cli.Command{
				Name:    "Scan",
				Aliases: []string{"scan", "S", "s"},
				Usage:   "Does a TCP port scan of the main TCP ports. Also accepts port numbers as argument with flag --ports",
				Flags:   flags,
				Action:  Scan,
			},
		},
	}

	return &app
}

func Scan(c *cli.Context) error {
	if err := result.populate(c); err != nil {
		return err
	}

	for _, port := range result.ports {
		result.addr = fmt.Sprintf("%s:%s", result.ip, port)

		conn, err := net.DialTimeout("tcp", result.addr, time.Second*3)
		// Will check whether a connection is closed or filtered
		if err != nil {
			// If the error is a timeout, the port is filtered
			var nerr net.Error
			if errors.As(err, &nerr) && nerr.Timeout() {
				fmt.Printf("Port %s is open | filtered\n", port)
				result.filtered++
				continue
			}

			// If user decided to keep closed hidden, it will not be printed
			if c.Bool("ShowClosed") {
				fmt.Printf("Port %s is CLOSED\n", port)
			}
			result.closed++
			continue
		}

		fmt.Printf("Port %s is OPEN\n", port)
		result.open++

		conn.Close()
	}
	if result.open == 0 && result.filtered == 0 {
		fmt.Println("------------------------------------------------")
		fmt.Printf("All scanned ports for %s are closed :(\n", result.ip)
		return nil
	}
	fmt.Println("------------------------------------------------")
	fmt.Printf("Port scan for ip %s completed.\nScanned ports: %d\nOpen ports: %d\nFiltered ports: %d\nClosed ports: %d\n", result.ip, result.scanned, result.open, result.filtered, result.closed)
	return nil
}

func uScan(c *cli.Context) error {
	result.populate(c)

	return nil
}

// populate(c) populates result struct, which holds scan data.
// It also validates the fields that can be altered by the user
func (result *scanResult) populate(c *cli.Context) error {
	// Populates and validade "ip" field
	result.ip = c.String("ip")
	if net.ParseIP(result.ip) == nil {
		return fmt.Errorf("\nInvalid IP format: %s", result.ip)
	}

	// Populates and validade "ports" field
	result.ports = c.StringSlice("ports")
	for _, port := range result.ports {
		if _, err := strconv.ParseUint(port, 10, 16); err != nil {
			return fmt.Errorf("\n%s is not a valid port.", port)
		}
	}
	result.scanned = uint(len(result.ports))
	return nil
}
