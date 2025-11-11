package scanner

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// ValidateIP checks wheter an IP address is valid
func ValidateIP(ip string) error {
	if net.ParseIP(ip) == nil {
		return fmt.Errorf("\nInvalid IP format: %s", ip)
	}
	return nil
}

// ValidatePorts checks whether ports were provided and assigns common defaults based on the connection type.
// It also tries to conver each argument into an uint16, if it fails, the port is not valid
func ValidatePorts(connType string, result *ScanResult) error {
	if len(result.ports) == 0 {
		switch connType {
		case "udp":
			result.ports = []string{"53", "67", "68", "69", "123", "161", "162", "500", "514", "3478", "4500"}
		case "tcp":
			result.ports = []string{"20", "21", "22", "23", "25", "80", "110", "139", "143", "443", "445", "3306", "3389", "5432", "8080"}
		}
	}

	firstArgumentIsRange := strings.Contains(result.ports[0], "-")

	// If a port can't be converted to a base 10 uint16 number, then it is not valid.
	// breaks immediately if the user settled a range of numbers using "-"
	for _, port := range result.ports {
		if _, err := strconv.ParseUint(port, 10, 16); err != nil {
			if firstArgumentIsRange {
				break
			}
			return fmt.Errorf("\n%s is not a valid port number.", port)
		}
	}

	// If the first argument is a range of numbers separated by "-", then the ports scanned will be the ones within this range
	// If this feature opts to be used, the user will not be able to put more arguments
	if firstArgumentIsRange {
		// This will restrict the amount of arguments allowed
		if argumentsAmount := len(result.ports); argumentsAmount > 1 {
			return fmt.Errorf("\nYou can't add %d arguments.\nTo select a range of ports, the number of arguments for the flag --ports must be just one.", argumentsAmount)
		}

		// This part will assign the range's beginning and end into two vars
		RangeStart, err := strconv.ParseUint(strings.Split(result.ports[0], "-")[0], 10, 16)
		if err != nil {
			return fmt.Errorf("\n%s is not a valid port number.", result.ports[0])
		}
		RangeEnd, _ := strconv.ParseUint(strings.Split(result.ports[0], "-")[1], 10, 16)
		if err != nil {
			return fmt.Errorf("\n%s is not a valid port number.", result.ports[0])
		}

		if RangeStart > RangeEnd {
			return fmt.Errorf("\nThe beginning of the range (%d) can't be higher than the end (%d).", RangeStart, RangeEnd)
		}

		// This part will iterate to the settled range and append each element to the slice
		for i := RangeStart; i <= RangeEnd; i++ {
			valueToString := strconv.Itoa(int(i))
			result.ports = append(result.ports, valueToString)
		}

		// Takes the range out of the slice
		result.ports = result.ports[1:]

		return nil
	}
	return nil
}
