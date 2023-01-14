package main

import (
	"log"

	"github.com/joho/godotenv"
)

func main() {
	if err := godotenv.Load(); err != nil {
		log.Fatal(err)
	}
	server, err := NewServer()
	if err != nil {
		log.Fatal(err)
	}
	server.Run()
}
