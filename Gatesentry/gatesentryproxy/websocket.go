package gatesentryproxy

import (
	"crypto/sha1"
	"encoding/base64"
	"log"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		// Allow all connections by default (for demonstration purposes).
		// In production, you should validate the origin.
		return true
	},
}

func computeAcceptKey(key string) string {
	// Concatenate the key with the WebSocket GUID
	guid := "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	hash := sha1.Sum([]byte(key + guid))

	// Encode the hash in base64
	return base64.StdEncoding.EncodeToString(hash[:])
}

func HandleWebsocketConnection(r *http.Request, w http.ResponseWriter) {

	respHeader := make(http.Header)

	// Use the gorilla/websocket library to upgrade the connection
	clientConn, err := upgrader.Upgrade(w, r, respHeader)
	if err != nil {
		log.Printf("Failed to upgrade client connection: %v", err)
		return
	}
	defer clientConn.Close()
	// Extract the backend URL from the request (e.g., from a query parameter).
	backendURL := url.URL{
		Scheme:   "ws", // Use "ws" for local neko connection
		Host:     r.URL.Host,
		Path:     r.URL.Path,
		RawQuery: r.URL.RawQuery, // Preserve the query string.
	}

	log.Println("websocket is " + backendURL.String())

	// Forward the original headers to the backend server.
	headers := http.Header{}
	for key, values := range r.Header {
		for _, value := range values {
			headers.Add(key, value)
		}
	}
	// Connect to the backend WebSocket server.
	backendConn, _, err := websocket.DefaultDialer.Dial(backendURL.String(), nil)
	if err != nil {
		log.Printf("Failed to connect to backend: %v", err)
		http.Error(w, "Failed to connect to backend", http.StatusBadGateway)
		return
	}
	defer backendConn.Close()

	errChan := make(chan error, 2)
	var wg sync.WaitGroup
	wg.Add(2)

	// Helper function for forwarding messages and signaling errors.
	forward := func(dst, src *websocket.Conn, direction string) {
		defer wg.Done()
		for {
			messageType, message, err := src.ReadMessage()
			if err != nil {
				log.Printf("Error reading from %s: %v", direction, err)
				errChan <- err
				return
			}
			//log.Printf("Forwarding message from %s: %s", direction, string(message))
			if err := dst.WriteMessage(messageType, message); err != nil {
				log.Printf("Error writing to destination in %s: %v", direction, err)
				errChan <- err
				return
			}
		}
	}
	// Start goroutines to forward messages in both directions.
	go forward(clientConn, backendConn, "backend")
	go forward(backendConn, clientConn, "client")

	// Wait until one of the directions reports an error or a timeout is reached.
	select {
	case err := <-errChan:
		log.Printf("Connection error occurred: %v", err)
	case <-time.After(10 * time.Minute): // Optional: Timeout to prevent indefinite blocking.
		log.Println("Timeout reached, closing connections")
	}

	// Ensure both connections are closed.
	clientConn.Close()
	backendConn.Close()

	// Wait for both goroutines to exit.
	wg.Wait()

}
