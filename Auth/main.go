package main

import (
	"github.com/Aran404/goauth/Auth/cmd"
	log "github.com/Aran404/goauth/Internal/Logger"
	utils "github.com/Aran404/goauth/Internal/Utils"
	"github.com/joho/godotenv"
)

func init() {
	if err := godotenv.Load(); err != nil {
		log.Fatal(log.GetStackTrace(), "No .env file found")
	}

	utils.Clear()
	utils.SetTitle("github.com/Aran404/goauth - Auth POC - Auth Server")
}

func main() {
	cmd.Execute()
}
