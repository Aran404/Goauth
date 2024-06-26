package cmd

import (
	"context"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	crypto "github.com/Aran404/goauth/Internal/Crypto"
	redis "github.com/Aran404/goauth/Internal/Database/Redis"
	log "github.com/Aran404/goauth/Internal/Logger"
	server "github.com/Aran404/goauth/Internal/Server"
	"github.com/dgrr/fastws"
	"github.com/joho/godotenv"
	"github.com/spf13/cobra"
	"github.com/valyala/fasthttp"
)

var (
	Signal chan os.Signal

	rootCmd = &cobra.Command{
		Use:   "Auth",
		Short: "Auth Server",
	}

	genCmd = &cobra.Command{
		Use:   "gen",
		Short: "Generates keys.",
		Long:  `Generates Cryptographically Secure keys.`,
		Run: func(cmd *cobra.Command, args []string) {
			apiSize := cmd.Flag("api-key-size").Value.String()
			jwtSize := cmd.Flag("jwt-token-size").Value.String()

			apiSizeInt, err := strconv.Atoi(apiSize)
			if err != nil {
				log.Fatal(log.GetStackTrace(), "ApiKey is not a number: %v", err.Error())
			}

			jwtSizeInt, err := strconv.Atoi(jwtSize)
			if err != nil {
				log.Fatal(log.GetStackTrace(), "JWTKey is not a number: %v", err.Error())
			}

			apiKey, err := crypto.GenerateAPIKey(apiSizeInt)
			if err != nil {
				log.Fatal(log.GetStackTrace(), "Could not generate API key: %v", err.Error())
			}

			jwtToken := crypto.GenerateJWTKey(jwtSizeInt)

			cmd.Println("API Key: " + apiKey)
			cmd.Println("JWT Token: " + jwtToken)

			envMap, err := godotenv.Read(".env")
			if err != nil {
				envMap = make(map[string]string)
			}

			envMap["API_KEY"] = apiKey
			envMap["JWT_SECRET"] = jwtToken

			if err := godotenv.Write(envMap, ".env"); err != nil {
				log.Fatal(log.GetStackTrace(), "Could not write .env file: %v", err.Error())
			}
		},
	}

	startCmd = &cobra.Command{
		Use:   "start",
		Short: "Starts the auth server",
		Long:  `Starts the websocket & HTTP server along with the redis client and the mongo client.`,
		Run: func(cmd *cobra.Command, args []string) {
			Start()
		},
	}
)

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		log.Fatal(log.GetStackTrace(), err.Error())
	}
}

func init() {
	rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
	rootCmd.AddCommand(genCmd, startCmd)
	genCmd.PersistentFlags().IntP("api-key-size", "a", 32, "Size of the API key")
	genCmd.PersistentFlags().IntP("jwt-token-size", "j", 32, "Size of the JWT key")

	Signal = make(chan os.Signal, 1)
	signal.Notify(Signal, syscall.SIGINT, syscall.SIGTERM)
}

func Start() {
	redisPort := os.Getenv("REDIS_PORT")
	if redisPort == "" {
		redisPort = "6379"
	}

	httpPort := os.Getenv("HTTP_PORT")
	if httpPort == "" {
		httpPort = "5920"
	}

	wsPort := os.Getenv("WS_PORT")
	if wsPort == "" {
		wsPort = "2255"
	}

	ctx := context.Background()
	rdb := redis.NewClient(ctx, "localhost:"+redisPort)
	jwtSecret := []byte(os.Getenv("JWT_SECRET"))
	s := server.NewServer(ctx, rdb, jwtSecret)

	go func() {
		if err := fasthttp.ListenAndServe(":"+wsPort, fastws.Upgrade(s.ServeHello)); err != nil {
			log.Error(log.GetStackTrace(), "Error starting server: %v", err)
		}
	}()

	go func() {
		s.DefaultOptions()
		s.Bind()

		if err := s.Start(httpPort); err != nil {
			log.Error(log.GetStackTrace(), "Error starting HTTP server: %v", err)
		}
	}()

	log.Info("Server started on port 8080")

	select {
	case <-ctx.Done():
		s.Clean()
	}
}
