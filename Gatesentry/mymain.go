package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	application "bitbucket.org/abdullah_irfan/gatesentryf"
	filters "bitbucket.org/abdullah_irfan/gatesentryf/filters"
	responder "bitbucket.org/abdullah_irfan/gatesentryf/responder"
	"bitbucket.org/abdullah_irfan/gatesentryproxy"
)

var GSPROXYPORT = "8080" // Updated port number
var GSBASEDIR = ""
var GATESENTRY_VERSION = "1.17.3"
var GS_BOUND_ADDRESS = ":"
var R *application.GSRuntime

var (
	configPath string
)

const (
	PORT = ":8001"
)

// Config holds the configuration from the JSON file
type Config struct {
	CertData             string   `json:"cert_data"`
	KeyData              string   `json:"key_data"`
	GoogleAllowedDomains []string `json:"google_allowed_domains"`
	PacFileData          string   `json:"pac_file_data"`
}

var (
	DIRECTORY  string
	LOCAL_PAC  string
	LOCAL_FILE string
)

type customHandler struct {
	http.Handler
}

// Function to write JSON data to a file (overwrite mode)
func saveJSONToFile(filename string, data interface{}) error {
	// Convert struct (or map) to JSON format
	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}

	// Write JSON data to the file (overwrite mode)
	return ioutil.WriteFile(filename, jsonData, 0644)
}

func rewrite_json_files(result map[string]interface{}, site string, file string) {

	value, exists := result[site]
	if !exists {
		fmt.Printf("Warning: Key '%s' not found in JSON. Skipping...\n", site)
		return
	}

	// Ensure it's a map
	blocked, ok := value.(map[string]interface{})
	if !ok {
		fmt.Printf("Warning: Key '%s' is not a valid JSON object. Skipping...\n", site)
		return
	}

	output, err := json.MarshalIndent(blocked, "", "  ") // Pretty format

	fmt.Printf("Parsed Config: %+v\n", output)

	err = saveJSONToFile(file, blocked)

	if err != nil {
		fmt.Println("Error saving JSON:", err)
		return
	}
}

func updateConfigData(data []byte) {
	var result map[string]interface{}
	err := json.Unmarshal([]byte(data), &result)
	if err != nil {
		fmt.Println("Error decoding JSON:", err)
		return
	}
	// List of JSON files to process
	jsonFiles := map[string]string{
		"blockedsites":      "filterfiles/blockedsites.json",
		"exceptionsitelist": "filterfiles/exceptionsitelist.json",
		"donotbump":         "filterfiles/dontbump.json",
	}

	// Loop through each file and process it
	for key, file := range jsonFiles {
		rewrite_json_files(result, key, file)
	}
}

func (h *customHandler) ServeHTTPPAC(w http.ResponseWriter, r *http.Request) {
	log.Printf("Request received: %s %s\n", r.Method, r.URL.Path)

	// Serve local.pac file when requested explicitly
	if r.URL.Path == LOCAL_PAC {
		log.Println("Serving local.pac file")
		http.ServeFile(w, r, LOCAL_FILE)
		return
	}

	// Serve index.html or any other default page for "/"
	if r.URL.Path == "/" {
		file := filepath.Join(DIRECTORY, "index.html") // Replace with your default file name
		log.Printf("Serving default file: %s\n", file)
		http.ServeFile(w, r, file)
		return
	}

	// Serve static files from the directory for other requests
	log.Printf("Serving static file: %s\n", r.URL.Path)
	h.Handler.ServeHTTP(w, r)
}

func main() {
	log.Println("starting go proxy for tls-termination")

	// Check if the config path is provided as an argument
	if len(os.Args) < 2 {
		log.Fatalf("Usage: %s /path/to/config.json", os.Args[0])
	}

	// Get the config path from the command-line arguments
	configPath := os.Args[1]
	gatesentryproxy.Setpath(configPath)

	// Read the JSON configuration file
	configFile, err := ioutil.ReadFile(configPath)
	if err != nil {
		log.Fatalf("Error reading config file: %v", err)
	}

	var config Config
	err = json.Unmarshal(configFile, &config)
	if err != nil {
		log.Fatalf("Error parsing config file: %v", err)
	}

	updateConfigData(configFile)

	// Remove any potential newlines or whitespaces from the encoded strings
	certDataClean := strings.TrimSpace(config.CertData)
	keyDataClean := strings.TrimSpace(config.KeyData)

	// Decode the certificate and key data
	certPEMBlock, err := base64.StdEncoding.DecodeString(certDataClean)
	if err != nil {
		log.Fatalf("Failed to decode certificate PEM block: %v", err)
	}
	keyPEMBlock, err := base64.StdEncoding.DecodeString(keyDataClean)
	if err != nil {
		log.Fatalf("Failed to decode private key PEM block: %v", err)
	}

	// Fetch and print other JSON values
	log.Println("Google Allowed Domains:")
	for _, domain := range config.GoogleAllowedDomains {
		log.Printf("- %s\n", domain)
	}

	log.Printf("PAC File Data: %s\n", config.PacFileData)

	// Start the Gatesentry proxy concurrently
	go RunGateSentry(certPEMBlock, keyPEMBlock)

	// Get the directory of the provided config file
	configDir := filepath.Dir(configPath)
	log.Printf("Config Directory: %s\n", configDir)

	// Create the PAC file path
	pacFilePath := filepath.Join(configDir, "local.pac")

	// Write PAC file data to the local.pac file
	err = ioutil.WriteFile(pacFilePath, []byte(config.PacFileData), 0644)
	if err != nil {
		log.Fatalf("Error writing PAC file: %v", err)
	}

	log.Printf("PAC file created at: %s\n", pacFilePath)

	// Create a custom handler with a file server for the specified directory
	handler := &customHandler{http.FileServer(http.Dir(configDir))}

	// Start the HTTP server
	log.Printf("Server is listening at %s\n", PORT)
	if err := http.ListenAndServe(PORT, handler); err != nil {
		log.Printf("Failed to start server: %s\n", err)
	}
}

// Define the RunGateSentry function here or import it if it's in another file
func RunGateSentry(certData, keyData []byte) {

	// Initialize GateSentry application and proxy
	R = application.Start(0) // Assuming web admin port is not used anymore
	R.BoundAddress = &GS_BOUND_ADDRESS

	application.StartBonjour()
	gatesentryproxy.InitProxy()
	ngp := gatesentryproxy.NewGSProxy()

	ngp.AuthHandler = func(authheader string) bool {
		log.Println("Auth header = " + authheader)
		return R.IsUserValid(authheader)
	}

	ngp.ContentHandler = func(gafd *gatesentryproxy.GSContentFilterData) {
		if strings.Contains(gafd.ContentType, "html") {
			responder := &responder.GSFilterResponder{Blocked: false}
			application.RunFilter("text/html", string(gafd.Content), responder)
			if responder.Blocked {
				gafd.FilterResponseAction = gatesentryproxy.ProxyActionBlockedTextContent
			}
		} else {
			if R.GSSettings.Get("enable_ai_image_filtering") == "true" && R.GSSettings.Get("ai_scanner_url") != "" {
				ai_service_url := R.GSSettings.Get("ai_scanner_url")
				filters.FilterImagesAI(gafd, ai_service_url)
			}
		}
	}

	ngp.DoMitm = func(host string) bool {
		enable_filtering := "true"
		if enable_filtering == "true" {
			responder := &responder.GSFilterResponder{Blocked: false}
			application.RunFilter("url/https_dontbump", host, responder)
			if responder.Blocked {
				return false
			}
		}
		return enable_filtering == "true"
	}

	ngp.ContentSizeHandler = func(gafd gatesentryproxy.GSContentSizeFilterData) {
		length := gafd.ContentSize
		go func() {
			R.UpdateUserData(gafd.User, uint64(length))
			R.UpdateConsumption(length)
		}()
	}

	ngp.ContentTypeHandler = func(gafd *gatesentryproxy.GSContentTypeFilterData) {
		contentType := gafd.ContentType
		responder := &responder.GSFilterResponder{Blocked: false}
		application.RunFilter("url/all_blocked_mimes", contentType, responder)
		if responder.Blocked {
			if contentType == "image/png" || contentType == "image/jpeg" || contentType == "image/jpg" || "image/gif" == contentType || "image/webp" == contentType {
				transparentImageBytes, _ := filters.Asset("app/transparent.png")
				gafd.FilterResponseAction = gatesentryproxy.ProxyActionBlockedFileType
				gafd.FilterResponse = transparentImageBytes
			} else {
				gafd.FilterResponseAction = gatesentryproxy.ProxyActionBlockedFileType
			}
		}
	}

	ngp.TimeAccessHandler = func(gafd *gatesentryproxy.GSTimeAccessFilterData) {
		blockedtimes := R.GSSettings.Get("blocktimes")
		responder := &responder.GSFilterResponder{Blocked: false}
		timezone := R.GSSettings.Get("timezone")
		filters.RunTimeFilter(responder, blockedtimes, timezone)
		if responder.Blocked {
			// Handle blocked time response if needed
		}
	}

	ngp.IsExceptionUrl = func(url string) bool {
		host := url
		responder := &responder.GSFilterResponder{Blocked: false}
		application.RunFilter("url/all_exception_urls", host, responder)
		return responder.Blocked
	}

	ngp.UserAccessHandler = func(gafd *gatesentryproxy.GSUserAccessFilterData) {
		log.Println("Running user access handler")
		if R.UserExists(gafd.User) {
			if R.IsUserActive(gafd.User) {
				gafd.FilterResponseAction = gatesentryproxy.ProxyActionUserActive
			} else {
				gafd.FilterResponseAction = gatesentryproxy.ProxyActionBlockedInternetForUser
				gafd.FilterResponse = []byte(responder.BuildGeneralResponsePage([]string{"Your access has been disabled by the administrator of this network."}, -1))
			}
		} else {
			gafd.FilterResponseAction = gatesentryproxy.ProxyActionUserNotFound
		}
	}

	ngp.IsAuthEnabled = func() bool {
		temp := R.GSSettings.Get("EnableUsers")
		return temp == "true"
	}

	ngp.UrlAccessHandler = func(gafd *gatesentryproxy.GSUrlFilterData) {
		host := gafd.Url
		responder := &responder.GSFilterResponder{Blocked: false}
		application.RunFilter("url/all_blocked_urls", host, responder)
		if responder.Blocked {
			gafd.FilterResponseAction = gatesentryproxy.ProxyActionBlockedUrl
		}
	}

	ngp.LogHandler = func(gafd gatesentryproxy.GSLogData) {
		url := gafd.Url
		user := gafd.User
		actionTaken := string(gafd.Action)
		R.Logger.LogProxy(url, user, actionTaken)
	}

	ngp.ProxyErrorHandler = func(gafd *gatesentryproxy.GSProxyErrorData) {
		msg := "Proxy Error. Unable to fulfill your request. <br/><strong>" + gafd.Error + "</strong>."
		switch gafd.Error {
		case "EOF":
			msg = "Proxy Error. Unable to fulfill your request at this time. Please try again in a few seconds."
		default:
		}
		gafd.FilterResponse = []byte(responder.BuildGeneralResponsePage([]string{msg}, -1))
	}

	addr := "0.0.0.0:" + GSPROXYPORT

	ttt := time.NewTicker(time.Second * 10)
	portavailable := false
	for {
		log.Println("Listening for proxy connections on : " + GSPROXYPORT)
		ln, err := net.Listen("tcp", ":"+GSPROXYPORT)
		if err != nil {
			log.Println("Port is not open for proxy")
		} else {
			portavailable = true
			err = ln.Close()
			log.Println("Listening on address:", ln.Addr().String())
			boundAddresses := []string{}
			host, _ := os.Hostname()
			addrs, _ := net.LookupIP(host)
			for _, addr := range addrs {
				if ipv4 := addr.To4(); ipv4 != nil {
					boundAddresses = append(boundAddresses, ipv4.String()+":"+GSPROXYPORT)
				}
			}
			GS_BOUND_ADDRESS = strings.Join(boundAddresses, ",")
		}

		if portavailable {
			break
		}
		<-ttt.C
	}

	//fmt.Printf("Certificate block: %s\n", certData)
	//fmt.Printf("Key block: %s\n", certData)

	// Initialize with the data from the PEM files
	gatesentryproxy.InitWithDataCerts(certData, keyData)
	//capembytes := []byte(R.GSSettings.Get("capem"))
	//keypembytes := []byte(R.GSSettings.Get("keypem"))

	//log.Printf("capembytes is = %s ", capembytes)
	//log.Printf("keypembytes is = %s ", keypembytes)
	proxyListener, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatal(err)
	}
	proxyHandler := gatesentryproxy.ProxyHandler{Iproxy: ngp}

	server := http.Server{Handler: proxyHandler}
	log.Printf("Starting up...Listening on = " + addr)
	err = server.Serve(tcpKeepAliveListener{proxyListener.(*net.TCPListener)})
	log.Fatal(err)
}

type tcpKeepAliveListener struct {
	*net.TCPListener
}
