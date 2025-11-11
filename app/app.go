package application

import (
	scan "github.com/KhaledLemes/potmap/scanner"
	"github.com/urfave/cli/v2"
)

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
				Usage:   "Does a TCP port scan of the main TCP ports. Accepts port numbers as argument with flag --ports",
				Flags:   flags,
				Action:  scan.TCPScan,
			},
			&cli.Command{
				Name:    "uScan",
				Aliases: []string{"uscan", "usc", "us"},
				Usage:   "Does a UDP port scan of the main ports. Also accepts port numbers as argument with flag --ports",
				Flags:   flags,
				Action:  scan.UDPScan,
			},
		},
	}

	return &app
}
