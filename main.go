package main

import (
	"log"
	"os"

	application "github.com/KhaledLemes/potmap/app"
)

func main() {
	application := application.Generate()
	if err := application.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}
