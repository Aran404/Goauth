package http

import (
	"net/http"
	"time"

	websocket "github.com/Aran404/goauth/Client/Websocket"
)

type Client struct {
	*websocket.Client
	H    *http.Client
	Host string
}

type Response struct {
	Raw    *http.Response
	Signed int8
	Body   []byte
	Status int
	Ok     bool
	Error  error
	JSON   map[string]any
}

func NewClient(c *websocket.Client, host string) *Client {
	return &Client{
		Host:   host,
		Client: c,
		H: &http.Client{
			Timeout: time.Second * 5,
			Transport: &http.Transport{
				// We want to make sure to end the connection at the end of the license request.
				MaxIdleConnsPerHost: 100,
				// We don't want active connections (Can be hijacked)
				DisableKeepAlives: true,
				MaxIdleConns:      1,
				MaxConnsPerHost:   1,
			},
		},
	}
}
