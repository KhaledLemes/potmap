package scanner

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/urfave/cli/v2"
)

type ScanResult struct {
	ip    string
	ports []string
	addr  string

	scanned  uint
	open     uint
	closed   uint
	filtered uint

	finalResult string
}

// Populates result struct, which holds scan data.
// It also validates the fields that can be altered by the user
func (result *ScanResult) populate(connType string, c *cli.Context) error {

	// Populates and validade "ip" field
	result.ip = c.String("ip")
	if err := ValidateIP(result.ip); err != nil {
		return err
	}

	// Populates and validade "ports" field
	result.ports = c.StringSlice("ports")
	if err := ValidatePorts(connType, result); err != nil {
		return err
	}

	// Populates "scanned" field
	result.scanned = uint(len(result.ports))
	return nil
}

// Prints the final output. Depending on the amount of closed ports, the output format may change
func (result *ScanResult) printFinalOutput(c *cli.Context) {
	if result.open == 0 && result.filtered == 0 {
		if !c.Bool("showclosed") {
			result.finalResult += "    Wow, such empty\n"
		}
		result.finalResult += fmt.Sprintf("------------------------\n\nAll scanned ports for %s are closed :(\n", result.ip)
	} else {
		result.finalResult += fmt.Sprintf("------------------------\n\nPort scan for ip %s completed.\nScanned ports: %d\nOpen ports: %d\nFiltered ports: %d\nClosed ports: %d\n", result.ip, result.scanned, result.open, result.filtered, result.closed)
	}
	fmt.Println(result.finalResult)
}

func TCPScan(c *cli.Context) error {
	result := &ScanResult{}
	if err := result.populate("tcp", c); err != nil {
		return err
	}

	fmt.Printf("%s\n------------------------\n", result.ip)
	for _, port := range result.ports {
		result.addr = fmt.Sprintf("%s:%s", result.ip, port)

		conn, err := net.DialTimeout("tcp", result.addr, time.Second*3)
		// Will check whether a connection is closed or filtered
		if err != nil {
			// If the error is a timeout the port is filtered
			var nerr net.Error
			if errors.As(err, &nerr) && nerr.Timeout() {
				result.finalResult += fmt.Sprintf("Port %s is open | filtered\n", port)
				result.filtered++
				continue
			}

			// If user decided to keep closed hidden, it will not be printed
			if c.Bool("ShowClosed") {
				result.finalResult += fmt.Sprintf("Port %s is CLOSED\n", port)
			}
			result.closed++
			continue
		}

		result.finalResult += fmt.Sprintf("Port %s is OPEN\n", port)
		result.open++

		conn.Close()
	}

	// Prints the output depending on the amount of closed ports
	result.printFinalOutput(c)
	return nil
}

func UDPScan(c *cli.Context) error {
	result := &ScanResult{}
	if err := result.populate("udp", c); err != nil {
		return err
	}

	fmt.Printf("%s\n------------------------\n", result.ip)

	for _, port := range result.ports {
		result.addr = fmt.Sprintf("%s:%s", result.ip, port)

		conn, err := net.DialTimeout("udp", result.addr, time.Second*3)
		if err != nil {
			result.finalResult += fmt.Sprintf("Unable to stablish connection with %s\n", result.addr)
			continue
		}
		defer conn.Close()

		conn.SetReadDeadline(time.Now().Add(time.Second * 3))

		conn.Write([]byte("FUECOCO"))
		buf := make([]byte, 1024)

		_, err = conn.Read(buf)
		if err != nil {
			var nerr net.Error

			// If the error is a timeout we cannot assume it is opened nor closed for UDP conns
			if errors.As(err, &nerr) && nerr.Timeout() {
				result.finalResult += fmt.Sprintf("Port %s is OPEN | FILTERED\n", port)
				result.filtered++
				continue
			}

			// If the connection got refused port is closed
			if strings.Contains(err.Error(), "connection refused") {
				if c.Bool("ShowClosed") {
					result.finalResult += fmt.Sprintf("Port %s is CLOSED\n", port)
				}
				result.closed++
				continue
			}

			// Catches other generic errors assuming it is closed
			if c.Bool("ShowClosed") {
				result.finalResult += fmt.Sprintf("Port %s is CLOSED\n", port)
			}
			result.closed++
			continue
		}
		// If it gets to this point, it means a response was read, so it is open.
		result.finalResult += fmt.Sprintf("Port %s is OPEN\n", port)
		result.open++
	}

	// Prints the output depending on the amount of closed ports
	result.printFinalOutput(c)
	return nil
}