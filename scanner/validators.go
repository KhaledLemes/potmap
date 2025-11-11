package scanner

import (
	"fmt"
	"net"
)

func ValidateIP(ip string) error {
	if net.ParseIP(ip) == nil {
		return fmt.Errorf("\nInvalid IP format: %s", ip)
	}
	return nil
}
