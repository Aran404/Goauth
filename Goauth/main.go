package main

import (
	"github.com/Aran404/Goauth/Goauth/cmd"
	log "github.com/Aran404/Goauth/internal/logger"
	utils "github.com/Aran404/Goauth/internal/utils"
	"github.com/joho/godotenv"
)

func init() {
	if err := godotenv.Load(); err != nil {
		log.Fatal(log.GetStackTrace(), "No .env file found")
	}

	utils.Clear()
	utils.SetTitle("github.com/Aran404/Goauth - Auth POC - Auth Server")
}

func main() {
	cmd.Execute()
}
