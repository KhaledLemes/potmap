package main

import (
	"fmt"
	"log"
	"os"
	"time"

	application "github.com/KhaledLemes/potmap/app"
)

func main() {
	currentTime := time.Now()
	formattedTime := currentTime.Format("2006-01-02 15:04:05")

	fmt.Printf("Starting potscan at %v\n\n------------------------\n", formattedTime)

	application := application.Generate()
	if err := application.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}
