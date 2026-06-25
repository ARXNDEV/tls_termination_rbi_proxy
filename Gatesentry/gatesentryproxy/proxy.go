package gatesentryproxy

import (
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/h2non/filetype"
)

var IProxy *GSProxy
var MaxContentScanSize int64 = 1e8
var dialer = &net.Dialer{
	Timeout:   30 * time.Second,
	KeepAlive: 30 * time.Second,
}
var ip6Loopback = net.ParseIP("::1")
var httpTransport = &http.Transport{
	Proxy:                 http.ProxyFromEnvironment,
	Dial:                  dialer.Dial,
	TLSHandshakeTimeout:   10 * time.Second,
	ExpectContinueTimeout: 1 * time.Second,
}

func NewGSProxyPassthru() *GSProxyPassthru {
	p := GSProxyPassthru{}
	p.ProxyActionToLog = ProxyActionFilterNone
	return &p
}

func NewGSHandler(handlerid string, f func(*[]byte, *GSResponder, *GSProxyPassthru)) *GSHandler {
	// h := GSHandler{Id: handlerid, Handle: f}
	// h.Handle = f;
	// return &h
	return nil
}

func NewGSProxy() *GSProxy {
	proxy := GSProxy{}
	IProxy = &proxy
	IProxy.UsersCache = map[string]GSUserCached{}
	return &proxy
}

func (p *GSProxy) RegisterHandler(id string, f func(*[]byte, *GSResponder, *GSProxyPassthru)) {
	h := NewGSHandler(id, f)
	if p.Handlers == nil {
		p.Handlers = map[string][]*GSHandler{}
	}
	log.Printf("Registering Handler for " + id)
	mm, ok := p.Handlers[id]
	if !ok {
		mm = ([]*GSHandler{})
		p.Handlers[id] = mm
	}
	p.Handlers[id] = append(p.Handlers[id], h)
}

func (p *GSProxy) RegisterAuthHandler(f func(authheader string) bool) {
	log.Println("Registering Auth Handler")
	p.AuthHandler = f
}

func (p *GSProxy) RunHandler(handlerid string, content *GSContentFilterData) {
	if p.Handlers[handlerid] != nil {
		for i := 0; i < len(p.Handlers[handlerid]); i++ {
			p.Handlers[handlerid][i].Handle(content)
		}
	}
}

func (p *GSProxy) RunAuthHandler(authheader string) bool {
	if p.AuthHandler != nil {
		return p.AuthHandler(authheader)
	}
	return false
}

func InitProxy() {
	CreateBlockedImageBytes()
	MaxContentScanSize = 1e8
}

type ProxyHandler struct {
	// TLS is whether this is an HTTPS connection.
	TLS bool

	// connectPort is the server port that was specified in a CONNECT request.
	connectPort string

	// user is a user that has already been authenticated.
	user string

	// rt is the RoundTripper that will be used to fulfill the requests.
	// If it is nil, a default Transport will be used.
	rt http.RoundTripper

	Iproxy *GSProxy
}

func decodeBase64Credentials(auth string) (user, pass string, ok bool) {
	auth = strings.TrimSpace(auth)
	enc := base64.StdEncoding
	buf := make([]byte, enc.DecodedLen(len(auth)))
	n, err := enc.Decode(buf, []byte(auth))
	if err != nil {
		return "", "", false
	}
	auth = string(buf[:n])

	colon := strings.Index(auth, ":")
	if colon == -1 {
		return "", "", false
	}

	return auth[:colon], auth[colon+1:], true
}

type DataPassThru struct {
	io.Writer
	Bytes []byte
	// total int64 // Total # of bytes transferred
	Contenttype string
	Passthru    *GSProxyPassthru
}

func (pt *DataPassThru) Write(p []byte) (int, error) {
	n, err := pt.Writer.Write(p)
	pt.Bytes = append(pt.Bytes, p...)
	if err == nil {
		IProxy.ContentSizeHandler(
			GSContentSizeFilterData{
				Url:         "",
				ContentType: pt.Contenttype,
				ContentSize: int64(n),
				User:        pt.Passthru.User,
			},
		)
	}
	return n, err
}

func (h ProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	// Log the incoming request details
	log.Printf("Received request: %s %s %s", r.Method, r.URL, r.Proto)
	log.Printf("Host: %s", r.Host)
	log.Printf("Remote Address: %s", r.RemoteAddr)
	log.Printf("User Agent: %s", r.UserAgent())

	// Check if the request is directed to google.com or any subdomain of google.com
	host := r.URL.Host
	log.Printf("Checking host: %s", host)
	if strings.HasSuffix(r.Host, ".google.com") || r.Host == "google.com" {
		// Add custom HTTP header for allowed domains
		w.Header().Set("X-GoogApps-Allowed-Domains", "accops.com")

		// Log the header addition
		log.Printf("Added X-GoogApps-Allowed-Domains header for request to %s", host)
	} else {
		// Log when no header is added
		log.Printf("No header added for request to %s", host)
	}

	passthru := NewGSProxyPassthru()

	hostaddress := strings.Split(r.URL.Host, ":")[0]
	isHostLanAddress := isLanAddress(hostaddress)

	if len(r.URL.String()) > 10000 {
		http.Error(w, "URL too long", http.StatusRequestURITooLong)
		return
	}

	client := r.RemoteAddr
	host, _, err := net.SplitHostPort(client)
	if err == nil {
		client = host
	}

	if r.URL.Scheme == "" {
		if h.TLS {
			r.URL.Scheme = "https"
		} else {
			r.URL.Scheme = "http"
		}
	}
	log.Printf("Scheme of the request is : %s ", r.URL.Scheme)
	if r.URL.Host == "" {
		if r.Host != "" {
			r.URL.Host = r.Host
		} else {
			log.Printf("Request from %s has no host in URL: %v", client, r.URL)
			time.Sleep(time.Second)
			http.Error(w, "No host in request URL, and no Host header.", http.StatusBadRequest)
			return
		}
	}

	authEnabled := true
	authEnabled = IProxy.IsAuthEnabled()
	user, _, authUser := HandleAuthAndAssignUser(r, passthru, h, authEnabled, client)
	if authEnabled {
		if user == "" || user == "127.0.0.1" {
			w.Header().Set("Proxy-Authenticate", "Basic realm="+"gsrealm")
			http.Error(w, "Proxy authentication required", http.StatusProxyAuthRequired)
			log.Printf("Missing required proxy authentication from %v to %v", r.RemoteAddr, r.URL)
			return
		} else {
			// _, userAuthStatus := IProxy.RunHandler("isaccessactive", "", &EMPTY_BYTES, passthru)
			userAccessFilterData := GSUserAccessFilterData{User: user}
			IProxy.UserAccessHandler(&userAccessFilterData)
			userAuthStatusString := userAccessFilterData.FilterResponseAction

			log.Println("User auth status = ", userAuthStatusString, " For user = ", user)
			if userAuthStatusString == ProxyActionUserNotFound {
				w.Header().Set("Proxy-Authenticate", "Basic realm="+"gsrealm")
				http.Error(w, "Proxy authentication required", http.StatusProxyAuthRequired)
				log.Printf("Missing required proxy authentication from %v to %v", r.RemoteAddr, r.URL)
				return
			}
			if userAuthStatusString != ProxyActionUserActive && !isHostLanAddress {
				sendBlockMessageBytes(w, r, nil, userAccessFilterData.FilterResponse, nil)
				return
			}
		}
	}

	action := ACTION_NONE

	// requestUrlBytes := []byte(r.URL.String())
	// isBlockedInternet, _ := IProxy.RunHandler(FILTER_USER_ACCESS_DISABLED, "", &requestUrlBytes, passthru)
	// userAccess := GSUserAccessFilterData{User: user}
	// IProxy.UserAccessHandler(&userAccess)
	// if userAccess.FilterResponseAction == (ProxyActionBlockedInternetForUser) {
	// 	// requestUrlBytes_log := []byte(r.URL.String())
	// 	passthru.ProxyActionToLog = ProxyActionBlockedInternetForUser
	// 	// IProxy.RunHandler("log", "", &requestUrlBytes_log, passthru)
	// 	IProxy.LogHandler(GSLogData{Url: r.URL.String(), User: user, Action: ProxyActionBlockedInternetForUser})
	// 	showBlockPage(w, r, nil, userAccess.FilterResponse)
	// 	return
	// }

	// timeblocked, _ := IProxy.RunHandler(FILTER_TIME, "", &EMPTY_BYTES, passthru)
	timefilterData := GSTimeAccessFilterData{Url: r.URL.String(), User: user}
	IProxy.TimeAccessHandler(&timefilterData)
	if timefilterData.FilterResponseAction == string(ProxyActionBlockedTime) {
		passthru.ProxyActionToLog = ProxyActionBlockedTime
		IProxy.LogHandler(GSLogData{Url: r.URL.String(), User: user, Action: ProxyActionBlockedTime})
		sendBlockMessageBytes(w, r, nil, timefilterData.FilterResponse, nil)
		return
	}

	if r.Method == "CONNECT" {
		hostport := r.URL.Host
		host, port, err := net.SplitHostPort(hostport)
		if err, ok := err.(*net.AddrError); ok && err.Err == "too many colons in address" {
			colon := strings.LastIndex(hostport, ":")
			host, port = hostport[:colon], hostport[colon+1:]
			if ip := net.ParseIP(host); ip != nil {
				r.URL.Host = net.JoinHostPort(host, port)
			}
		}
	}

	urlFilterData := GSUrlFilterData{Url: r.URL.String(), User: user}

	// isBlockedUrl, _ := IProxy.RunHandler(FILTER_ACCESS_URL, "", &requestUrlBytes, passthru)
	IProxy.UrlAccessHandler(&urlFilterData)

	if urlFilterData.FilterResponseAction == ProxyActionBlockedUrl {
		passthru.ProxyActionToLog = ProxyActionBlockedUrl
		IProxy.LogHandler(GSLogData{Url: r.URL.String(), User: user, Action: ProxyActionBlockedUrl})
		sendBlockMessageBytes(w, r, nil, urlFilterData.FilterResponse, nil)
		return
	}

	fileExt := getFileExtensionFromUrl(r.URL.String())
	fileMime := getMimeByExtension(fileExt)
	contentTypeScan := &GSContentTypeFilterData{Url: r.URL.String(), ContentType: fileMime}
	IProxy.ContentTypeHandler(contentTypeScan)

	log.Println("Url File extension = ", fileExt, " mime ", fileMime)

	if contentTypeScan.FilterResponseAction == ProxyActionBlockedFileType {
		passthru.ProxyActionToLog = ProxyActionBlockedFileType
		IProxy.LogHandler(GSLogData{Url: r.URL.String(), User: user, Action: ProxyActionBlockedFileType})
		r.URL.Host = "blocked.gatesentryguard.com"
		r.URL.Scheme = "https"
		r.URL.Path = "/file/gatesentryguard/blocked.svg"
		w.Header().Set("Location", r.URL.String())
		w.WriteHeader(http.StatusMovedPermanently)
		log.Println("Modified url = ", r.URL.String())
		// Must return: a redirect response has been written, so continuing to
		// proxy the content would double-write the response.
		return
	}

	if r.Method == "CONNECT" {
		action = ACTION_SSL_BUMP
	}

	// urlHostBytes := []byte(r.URL.Host)
	// shouldMitm, _ := IProxy.RunHandler("mitm", "", &urlHostBytes, passthru)
	shouldMitm := IProxy.DoMitm(r.URL.Host)
	// RBI: only bump/isolate the configured target hosts; tunnel everything else
	// (the proxied browser's telemetry/fonts/googleapis background traffic) so we
	// don't spawn a container per host and flood/starve the real session.
	if shouldMitm && !rbiShouldIsolate(r.URL.Host) {
		shouldMitm = false
	}
	log.Println("[TEST] Should MITM = ", shouldMitm, " currentAction = "+action, " for ", r.URL.String())

	if isHostLanAddress {
		log.Println("isHostlanAddress == true")
		action = ACTION_NONE
		// modified = true
	}

	if shouldMitm == false {
		log.Println("shouldMitm == false")
		action = ACTION_NONE
	}

	// isExceptionUrl, _ := IProxy.RunHandler("except_urls", "", &requestUrlBytes, passthru)
	isExceptionUrl := IProxy.IsExceptionUrl(r.URL.String())
	if isExceptionUrl {
		log.Println("isExceptionUrl == true")
		action = ACTION_NONE
	}

	if action == ACTION_SSL_BUMP {
		log.Println("action == ssl-bump")
		HandleSSLBump(r, w, user, authUser, passthru, IProxy)
		return
	}

	if r.Method == "CONNECT" {
		log.Println("websocket is  supported")
		// requestUrlBytes_log := []byte(r.URL.String())
		passthru.ProxyActionToLog = ProxyActionSSLDirect
		// IProxy.RunHandler("log", "", &requestUrlBytes_log, passthru)
		IProxy.LogHandler(GSLogData{Url: r.URL.String(), User: user, Action: ProxyActionSSLDirect})
		HandleSSLConnectDirect(r, w, user, passthru)
		return
	}

	// Only the user's TOP-LEVEL navigation should be turned into the RBI viewer.
	// The viewer (selkies) then makes its OWN sub-requests through this proxy —
	// /turn (ICE config JSON), JS/CSS assets, /webrtc/signalling — and those must
	// pass straight through to the backend, NOT get rewritten to the viewer HTML.
	// Gating on Sec-Fetch-Dest: document does that reliably (cookie alone was
	// fragile: a cookie-less /turn fetch returned index.html → "Unexpected token
	// '<'" → no ICE config → never connects).
	secDest := r.Header.Get("Sec-Fetch-Dest")
	isTopLevelNav := secDest == "document" ||
		(secDest == "" && strings.Contains(strings.ToLower(r.Header.Get("Accept")), "text/html"))

	// RBI isolation applies ONLY to hosts on the allowlist (rbiShouldIsolate).
	// Everything else — including the proxied browser's plain-HTTP telemetry
	// (clients2.google.com/time, *.gvt1.com extension updates, etc.) — must be
	// proxied straight through to its real origin, NOT forwarded to a container,
	// or every background host spawns its own throwaway session and floods/starves
	// the real stream. HTTPS is already gated via shouldMitm above, but plain-HTTP
	// requests fall through to here and need their own allowlist gate.
	rbiIsolate := rbiShouldIsolate(r.URL.Host)

	// Every top-level navigation to an ISOLATED host is turned into its OWN throwaway
	// per-session container and opened in a NEW window. Sub-resource/asset/XHR
	// requests are not document navigations, so they never trigger isolation.
	modifyURL := isTopLevelNav && rbiIsolate

	actual_url := r.URL.Scheme + "://" + r.URL.Host + string(r.URL.Path)
	var originalTitle string
	var rbiFavURL string
	if modifyURL {
		var favRel string
		originalTitle, favRel = fetchPageMetadata(actual_url)
		// Resolve the site's declared favicon to an absolute URL on its REAL origin.
		favAbs := favRel
		switch {
		case favRel == "":
			favAbs = r.URL.Scheme + "://" + r.URL.Host + "/favicon.ico"
		case strings.HasPrefix(favRel, "http://"), strings.HasPrefix(favRel, "https://"):
			// already absolute
		case strings.HasPrefix(favRel, "//"):
			favAbs = r.URL.Scheme + ":" + favRel
		case strings.HasPrefix(favRel, "/"):
			favAbs = r.URL.Scheme + "://" + r.URL.Host + favRel
		default:
			favAbs = r.URL.Scheme + "://" + r.URL.Host + "/" + favRel
		}
		// Embed the favicon as a self-contained data: URI. If we instead handed the
		// client the favicon URL on the isolated host, the tab-icon request would be
		// proxy-forwarded to the neko container and the tab would show NEKO's icon
		// instead of the site's. The server-side fetch hits the site's real origin.
		if dataURI, ferr := fetchFaviconBase64(favAbs); ferr == nil && dataURI != "" {
			rbiFavURL = dataURI
		} else {
			rbiFavURL = favAbs
			log.Printf("[rbi] favicon base64 fetch failed for %s: %v", favAbs, ferr)
		}
		log.Printf("[rbi] isolating top-level nav: %s (title=%q fav=%dB)", actual_url, originalTitle, len(rbiFavURL))
	}

	// Neko's viewer derives its asset + signaling-WebSocket base from the PAGE PATH
	// (location.pathname), not from <base>. Served under a sub-path (e.g. /gather) it
	// requests /gather/ws + /gather/*.json which 404 -> the stream never connects
	// (black screen). So for an isolated TOP-LEVEL nav whose path isn't root, launch
	// the session (the container still opens the FULL path) and 302-redirect the
	// CLIENT to the host root, so the viewer loads at "/" and neko connects cleanly.
	// (The host-keyed session is reused by the follow-up root request — same container.)
	if modifyURL && r.URL.Path != "" && r.URL.Path != "/" {
		if _, lerr := rbiLaunchSession(actual_url); lerr != nil {
			log.Printf("[rbi] launch failed for %s: %v", actual_url, lerr)
			http.Error(w, "RBI session failed to start: "+lerr.Error(), http.StatusBadGateway)
			return
		}
		rootURL := r.URL.Scheme + "://" + r.URL.Host + "/"
		log.Printf("[rbi] sub-path isolated nav -> redirect client to root: %s -> %s", actual_url, rootURL)
		http.Redirect(w, r, rootURL, http.StatusFound)
		return
	}

	// PROXY-FORWARD: for an ISOLATED host, every request is reverse-proxied to its
	// per-session container, so the stream is served on the SITE's OWN origin — the
	// client's URL bar stays youtube.com / www.google.com (no localhost). Launch or
	// reuse the host's throwaway container (host-keyed). Non-isolated hosts skip this
	// block entirely and are proxied to their real origin by the RoundTrip below.
	if rbiIsolate {
		rbiSess, lerr := rbiLaunchSession(actual_url)
		if lerr != nil {
			log.Printf("[rbi] launch failed for %s: %v", actual_url, lerr)
			IProxy.LogHandler(GSLogData{Url: actual_url, User: user, Action: ProxyActionFilterNone})
			http.Error(w, "RBI session failed to start: "+lerr.Error(), http.StatusBadGateway)
			return
		}

		// Set the forwarding target = this session's neko container. When the proxy
		// itself runs in Docker, RBI_FORWARD_HOST=host.docker.internal lets it reach
		// the per-session containers' host-published ports.
		forwardHost := rbiEnv("RBI_FORWARD_HOST", "127.0.0.1")
		forwardPort := strconv.Itoa(rbiSess.tcpPort)

		// Update the request URL and host to point at this session's container.
		r.Host = forwardHost
		r.URL.Host = net.JoinHostPort(forwardHost, forwardPort)
		r.URL.Scheme = "http"
		r.Proto = "HTTP/1.1"
		r.ProtoMajor = 1
		r.ProtoMinor = 1
	}

	if r.Header.Get("Upgrade") == "websocket" {
		log.Println("websocket is  supported....")
		HandleWebsocketConnection(r, w)
		return
	}

	if len(r.Header["X-Forwarded-For"]) >= 10 {
		http.Error(w, "Proxy forwarding loop", http.StatusBadRequest)
		log.Printf("Proxy forwarding loop from %s to %v", r.Header.Get("X-Forwarded-For"), r.URL)
		return
	}

	gzipOK := strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") && !isLanAddress(client)
	r.Header.Del("Accept-Encoding")

	var rt http.RoundTripper
	if r.URL.Scheme == "http" {
		rt = httpTransport
	} else if h.rt == nil {
		rt = httpTransport
	} else {
		rt = h.rt
	}

	if r.ContentLength == 0 {
		r.Body.Close()
		r.Body = nil
	}

	removeHopByHopHeaders(r.Header)

	log.Println(actual_url)
	if modifyURL {
		log.Println("Cookie 'rbi_accops' not found. Modifying URL path...")
		r.URL.Path = "/"

	} else {
		log.Println("Cookie 'rbi_accops' found. Keeping original path.")
	}

	/*	log.Printf("Printing Headers")
		for key, values := range r.Header {
			for _, value := range values {
				log.Printf("%s: %s\n", key, value)
			}
		}
	*/
	resp, err := rt.RoundTrip(r)
	if err != nil {
		log.Printf("error fetching %s: %s", r.URL, err)
		// errorBytes := []byte(err.Error())
		// IProxy.RunHandler("proxyerror", "", &errorBytes, passthru)
		errorData := &GSProxyErrorData{Error: err.Error()}
		IProxy.ProxyErrorHandler(errorData)
		sendBlockMessageBytes(w, r, nil, errorData.FilterResponse, nil)
		return
	}
	defer resp.Body.Close()

	contentType := strings.ToLower(resp.Header.Get("Content-Type"))
	if strings.Contains(contentType, ";") {
		t := strings.Split(contentType, ";")
		if len(t) > 0 {
			contentType = t[0]
		}
	}
	log.Println("Content type is = ", contentType, " for ", r.URL.String())
	// contentTypeBytes := []byte(contentType)

	// contentTypeStatusBlocked, _ := IProxy.RunHandler("contenttypeblocked", "", &contentTypeBytes, passthru)
	contentTypeData := GSContentTypeFilterData{Url: r.URL.String(), ContentType: contentType}
	IProxy.ContentTypeHandler(&contentTypeData)

	if contentTypeData.FilterResponseAction == ProxyActionBlockedFileType {
		// requestUrlBytes_log := []byte(r.URL.String())
		passthru.ProxyActionToLog = ProxyActionBlockedFileType
		// IProxy.RunHandler("log", "", &requestUrlBytes_log, passthru)
		IProxy.LogHandler(GSLogData{Url: r.URL.String(), User: user, Action: ProxyActionBlockedFileType})
		sendBlockMessageBytes(w, r, nil, BLOCKED_CONTENT_TYPE, &contentType)
		return
	}

	var buf bytes.Buffer
	limitedReader := &io.LimitedReader{R: resp.Body, N: int64(MaxContentScanSize)}
	teeReader := io.TeeReader(limitedReader, &buf)

	localCopyData, err := io.ReadAll(teeReader)

	//log.Printf("localCopyData is  %s", localCopyData)
	if modifyURL && strings.Contains(contentType, "html") {
		// Inject the SITE's real title + favicon into the served neko viewer HTML so
		// the tab reads e.g. "YouTube". The in-image script reads window.__rbi_title /
		// __rbi_fav and also auto-logs-in (adds usr/pwd client-side, then strips them)
		// so the URL bar stays the site's URL with no credentials leaked.
		qt := strings.ReplaceAll(strconv.Quote(originalTitle), "</", "<\\/")
		qf := strings.ReplaceAll(strconv.Quote(rbiFavURL), "</", "<\\/")
		// Neko's viewer ships several <link rel=icon> tags (favicon-32x32.png …) and
		// Chrome uses the rel="icon" ones for the tab icon. Strip them all and inject a
		// single data:-URI favicon for the real site, so the tab shows e.g. YouTube's
		// icon instead of neko's. (The baked JS tick only touched the FIRST icon link —
		// apple-touch-icon — so it never replaced the real favicon.)
		favLink := ""
		if strings.HasPrefix(rbiFavURL, "data:") {
			favLink = "<link rel=\"icon\" href=\"" + rbiFavURL + "\">"
		}
		// Camera-relay URL for the in-tab auto-camera (inject-head.html autoCam). The
		// relay runs on the VM host; the client reaches it at the same IP it uses for
		// WebRTC (RBI_NAT1TO1). Empty on loopback-only setups -> autoCam stays off.
		camURL := ""
		if ip := os.Getenv("RBI_NAT1TO1"); ip != "" && ip != "127.0.0.1" {
			camURL = "wss://" + ip + ":8443/ws"
		}
		// __rbi_cam="" DISABLES the baked (unreliable, on-demand control-channel) camStart
		// in inject-head.html; the proxy now drives a RELIABLE warm camera (rbiWarmCamera)
		// off __rbi_cam_url instead. Deployed via `go build` + proxy restart — no image rebuild.
		inject := favLink + "<script>window.__rbi_title=" + qt + ";window.__rbi_fav=" + qf + ";window.__rbi_cam=\"\";window.__rbi_cam_url=" + strconv.Quote(camURL) + ";</script>" + rbiWarmCamera + "</head>"
		s := string(localCopyData)
		s = rbiIconLinkRe.ReplaceAllString(s, "")
		// Neko's viewer, its assets and its signaling WebSocket are all ROOT-relative.
		// When the isolated URL has a sub-path (e.g. teams.live.com/gather), the browser
		// resolves them under /gather/ and they 404 -> WS never connects -> black screen.
		// Force a root <base> so every relative URL maps to the host root (a no-op for
		// sites isolated at "/").
		if i := strings.Index(s, "<head>"); i >= 0 {
			// rbiConsoleRebrand must be the FIRST thing in <head> so it overrides
			// console.* BEFORE neko's bundle captures a reference to it — otherwise
			// neko logs via its own saved console and bypasses any later override.
			s = s[:i+len("<head>")] + rbiConsoleRebrand + "<base href=\"/\">" + s[i+len("<head>"):]
		}
		if strings.Contains(s, "</head>") {
			s = strings.Replace(s, "</head>", inject, 1)
		}
		localCopyData = []byte(s)
	}

	if err != nil {
		log.Printf("error while reading response body (URL: %s): %s", r.URL, err)
	}

	if limitedReader.N == 0 {
		// Body is larger than MaxContentScanSize, so stream it through without
		// scanning. (The old code set Content-Encoding: gzip but never actually
		// gzipped the body, and fell through without returning — double-writing
		// the response and corrupting it.)
		log.Println("response body too long to filter:", r.URL)
		if resp.ContentLength > 0 {
			w.Header().Set("Content-Length", strconv.FormatInt(resp.ContentLength, 10))
		}

		copyResponseHeader(w, resp)

		destwithcounter := &DataPassThru{
			Writer:      w,
			Contenttype: contentType,
			Passthru:    passthru,
		}

		// Write the already-buffered head, then stream the remainder in order.
		destwithcounter.Write(localCopyData)
		if _, err := io.Copy(destwithcounter, resp.Body); err != nil {
			log.Printf("error while copying response (URL: %s): %s", r.URL, err)
			errorData := &GSProxyErrorData{Error: err.Error()}
			IProxy.ProxyErrorHandler(errorData)
			sendBlockMessageBytes(w, r, nil, errorData.FilterResponse, nil)
		}
		return
	}

	kind, _ := filetype.Match(localCopyData)
	if kind != filetype.Unknown {
		log.Printf("File type: %s. MIME: %s\n", kind.Extension, kind.MIME.Value)
		contentType = kind.MIME.Value
	}
	responseSentMedia, proxyActionTaken := ScanMedia(localCopyData, contentType, r, w, resp, buf, passthru)
	if responseSentMedia == true {
		passthru.ProxyActionToLog = proxyActionTaken
		// IProxy.RunHandler("log", "", &requestUrlBytes, passthru)
		IProxy.LogHandler(GSLogData{Url: r.URL.String(), User: user, Action: proxyActionTaken})
		return
	}

	responseSentText, proxyActionTaken := ScanText(localCopyData, contentType, r, w, resp, buf, passthru)
	log.Println("responseSentText is  ", responseSentText)
	if responseSentText == true {
		passthru.ProxyActionToLog = proxyActionTaken
		// IProxy.RunHandler("log", "", &requestUrlBytes, passthru)
		IProxy.LogHandler(GSLogData{Url: r.URL.String(), User: user, Action: proxyActionTaken})
		return
	}

	if gzipOK && len(localCopyData) > 1000 {
		resp.Header.Set("Content-Encoding", "gzip")
		copyResponseHeader(w, resp)
		gzw := gzip.NewWriter(w)
		var dest io.Writer
		dest = gzw
		destwithcounter := &DataPassThru{Writer: dest, Contenttype: contentType, Passthru: passthru}
		destwithcounter.Write(localCopyData)
		gzw.Close()
	} else {
		w.Header().Set("Content-Length", strconv.Itoa(len(localCopyData)))
		copyResponseHeader(w, resp)
		destwithcounter := &DataPassThru{Writer: w, Contenttype: contentType, Passthru: passthru}
		destwithcounter.Write(localCopyData)
	}
}

func sendInsecureBlockBytes(w http.ResponseWriter, r *http.Request, resp *http.Response, content []byte, contentType *string) {
	w.WriteHeader(http.StatusOK)
	// string ends with

	if contentType != nil && isImage(*contentType) {
		reasonForBlockArray := []string{"", "Image blocked by Gatesentry", "Reason(s) for blocking", "1. The content type is blocked"}
		emptyImage, _ := createEmptyImage(500, 500, "jpeg", reasonForBlockArray)
		w.Header().Set("Content-Type", "image/jpeg; charset=utf-8")
		w.Write(emptyImage)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(content)
}

func sendBlockMessageBytes(w http.ResponseWriter, r *http.Request, resp *http.Response, content []byte, contentType *string) {
	// check if request is https
	if strings.Contains(r.URL.String(), ":443") {
		log.Println("[Proxy] Sending block page for https request")
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			sendInsecureBlockBytes(w, r, resp, content, contentType)
			return
		}
		defer conn.Close()
		conn.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))

		//clientHello, err := gsClientHello.ReadClientHello(conn)

		tlsConfig, err := createSelfSignedTLSConfig()
		if err != nil {
			fmt.Println("[Proxy][Error:showBlockPage] Error creating self-signed certificate:", err)
			conn.Close()
			return
		}

		tlsConn := tls.Server(conn, tlsConfig)
		err = tlsConn.Handshake()
		if err != nil {
			log.Println("[Proxy][Error:showBlockPage] Handshake failed:", err)
			conn.Close()
			return
		}

		_, err = tlsConn.Write([]byte("HTTP/1.1 403 Forbidden\r\n"))
		if err != nil {
			log.Println("[Proxy][Error:showBlockPage] writing to connection", err)
			return
		}
		_, err = tlsConn.Write([]byte("Content-Type: text/html\r\n\r\n"))
		if err != nil {
			log.Println("[Proxy][Error:showBlockPage] Error writing to connection", err)
			conn.Close()
			return
		}
		_, err = tlsConn.Write(content)
		if err != nil {
			conn.Close()
			return
		}

		tlsConn.Close()
	} else {
		sendInsecureBlockBytes(w, r, resp, content, contentType)
	}

}

// copyResponseHeader writes resp's header and status code to w.
func copyResponseHeader(w http.ResponseWriter, resp *http.Response) {
	newHeader := w.Header()
	for key, values := range resp.Header {
		if key == "Content-Length" {
			continue
		}
		for _, v := range values {
			newHeader.Add(key, v)
		}
	}

	w.WriteHeader(resp.StatusCode)
}

// removeHopByHopHeaders removes header fields listed in
// http://tools.ietf.org/html/draft-ietf-httpbis-p1-messaging-14#section-7.1.3.1
func removeHopByHopHeaders(h http.Header) {
	toRemove := HOP_BY_HOP
	if c := h.Get("Connection"); c != "" {
		for _, key := range strings.Split(c, ",") {
			toRemove = append(toRemove, strings.TrimSpace(key))
		}
	}
	for _, key := range toRemove {
		h.Del(key)
	}
}

// A hijackedConn is a connection that has been hijacked (to fulfill a CONNECT
// request).
type hijackedConn struct {
	net.Conn
	io.Reader
}

func (hc *hijackedConn) Read(b []byte) (int, error) {
	return hc.Reader.Read(b)
}
func extractTitle(body string) string {
	titleStart := strings.Index(body, "<title>")
	titleEnd := strings.Index(body, "</title>")
	if titleStart == -1 || titleEnd == -1 || titleStart > titleEnd {
		return ""
	}
	return body[titleStart+len("<title>") : titleEnd]
}

func extractFavicon(body string) string {
	iconStart := strings.Index(body, "<link rel=\"icon\"")
	if iconStart == -1 {
		return ""
	}

	hrefStart := strings.Index(body[iconStart:], "href=\"")
	if hrefStart == -1 {
		return ""
	}

	hrefStart += iconStart + len("href=\"")
	hrefEnd := strings.Index(body[hrefStart:], "\"")
	if hrefEnd == -1 {
		return ""
	}

	return body[hrefStart : hrefStart+hrefEnd]
}
// rbiFetchClient is used for the server-side RBI metadata/favicon fetches; it
// has a timeout so a slow target cannot hang the request handler indefinitely.
var rbiFetchClient = &http.Client{Timeout: 10 * time.Second}

// rbiIconLinkRe matches any <link ... rel="...icon..."> tag (icon, shortcut icon,
// apple-touch-icon, mask-icon) so the neko viewer's OWN favicons can be stripped
// from the served HTML and replaced with the isolated site's real icon.
var rbiIconLinkRe = regexp.MustCompile(`(?i)<link\b[^>]*\brel=["'][^"']*icon[^"']*["'][^>]*>`)

// rbiConsoleRebrand is injected as the FIRST element inside <head> (before neko's
// own bundle runs) so it wraps console.* BEFORE neko captures a reference to it —
// otherwise neko logs through its own saved console and bypasses a later override.
// It white-labels the browser console: rebrands neko's "[NEKO]" log prefix (and any
// "neko" text) to the product name in orange, and drops the benign early
// RTCDataChannel race errors that fire before the data channel opens.
const rbiConsoleRebrand = `<script>(function(){try{var BR="Accops HySecure Dev",OR="color:#F26522;font-weight:bold";var DROP=/RTCDataChannel|InvalidStateError|readyState|sendData/;var rep=function(x){return (typeof x==="string")?x.replace(/\[NEKO\]/g,"["+BR+"]").replace(/n\.?eko/gi,BR):x;};["log","debug","info","warn","error","trace"].forEach(function(m){var o=console[m]?console[m].bind(console):function(){};console[m]=function(){try{var s="";for(var i=0;i<arguments.length;i++){s+=" "+arguments[i];}if(DROP.test(s))return;var a=Array.prototype.slice.call(arguments);if(typeof a[0]==="string"&&a[0].indexOf("%c")<0&&/\[NEKO\]|n\.?eko/i.test(a[0])){var t=a[0].replace(/\[NEKO\]/g,"["+BR+"]").replace(/n\.?eko/gi,BR);return o.apply(null,["%c"+t,OR].concat(a.slice(1)));}for(var j=0;j<a.length;j++){a[j]=rep(a[j]);}return o.apply(null,a);}catch(_){return o.apply(null,arguments);}};});}catch(e){}})();</script>`

// rbiWarmCamera is injected just before </head> (after __rbi_cam_url is set). neko v3 has no
// client webcam send-path, so on camera-relevant sites we capture the user's REAL camera
// (preferring a non-virtual device), with an 8s getUserMedia timeout + retry, and stream JPEG
// frames over wss to the camrelay /ws (which feeds /dev/video10 in the container). It is WARM:
// it fires on the FIRST user gesture (like the always-reliable mic) instead of the fragile
// on-demand control channel, and the WS auto-reconnects. This is what makes the camera reliable.
const rbiWarmCamera = `<script>(function(){try{var U=window.__rbi_cam_url||"";if(!U)return;if(!/teams|meet\.google|webcam|zoom|webex|whereby|skype|jitsi/i.test(location.hostname))return;var started=false;function pick(){return navigator.mediaDevices.enumerateDevices().then(function(ds){var vs=ds.filter(function(d){return d.kind==="videoinput";});var r=vs.find(function(d){return /facetime|built-in|macbook|internal/i.test(d.label);})||vs.find(function(d){return d.label&&!/obs|virtual|snap|manycam|loopback/i.test(d.label);});return r?r.deviceId:null;}).catch(function(){return null;});}function go(){if(started)return;started=true;pick().then(function(id){var c={video:{width:640,height:480,frameRate:15}};if(id)c.video.deviceId={ideal:id};var to=new Promise(function(_,r){setTimeout(function(){r(new Error("to"));},8000);});Promise.race([navigator.mediaDevices.getUserMedia(c),to]).then(function(s){var cv=document.createElement("canvas");cv.width=640;cv.height=480;var x=cv.getContext("2d");var hf=false;var trk=s.getVideoTracks()[0];function vidFallback(){var v=document.createElement("video");v.srcObject=s;v.muted=true;v.playsInline=true;v.autoplay=true;v.setAttribute("style","position:fixed;left:0;top:0;width:64px;height:48px;opacity:0.02;pointer-events:none;z-index:-1");document.body.appendChild(v);v.play().catch(function(){});setInterval(function(){if(v.videoWidth){try{x.drawImage(v,0,0,640,480);hf=true;}catch(_){}}},66);}if(window.MediaStreamTrackProcessor){try{var rd=new MediaStreamTrackProcessor({track:trk}).readable.getReader();(function pump(){rd.read().then(function(r){if(r.done)return;try{x.drawImage(r.value,0,0,640,480);hf=true;}catch(_){}try{r.value.close();}catch(_){}pump();}).catch(function(){});})();}catch(e){vidFallback();}}else{vidFallback();}function conn(){var ws;try{ws=new WebSocket(U);}catch(e){setTimeout(conn,1500);return;}ws.binaryType="arraybuffer";var t=null;ws.onopen=function(){t=setInterval(function(){if(ws.readyState!==1||!hf)return;try{cv.toBlob(function(b){if(b)b.arrayBuffer().then(function(a){try{ws.send(a);}catch(_){}});},"image/jpeg",0.6);}catch(_){}},66);};ws.onclose=function(){if(t){clearInterval(t);t=null;}setTimeout(conn,1500);};ws.onerror=function(){try{ws.close();}catch(_){}};}conn();}).catch(function(){started=false;setTimeout(go,3000);});});}["click","keydown","pointerdown"].forEach(function(e){document.addEventListener(e,go);});}catch(e){}})();</script>`

// NOTE: webcam passthrough was tested and is NOT achievable with neko v3's stock
// client — it has a mic toggle but no webcam control and only forwards the audio
// track when sharing, so an injected getUserMedia video track is dropped and never
// reaches the server's v4l2loopback feed (/dev/video10 stays empty). Camera would
// need a forked neko client or a different streamer (Kasm). Mic works fully.

func fetchPageMetadata(targetURL string) (string, string) {
	resp, err := rbiFetchClient.Get(targetURL)
	if err != nil {
		return "", ""
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)

	title := extractTitle(string(body))
	favicon := extractFavicon(string(body))

	if favicon == "" {
		favicon = "/favicon.ico"
	}
	return title, favicon
}

func fetchFaviconBase64(faviconURL string) (string, error) {
	resp, err := rbiFetchClient.Get(faviconURL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to fetch favicon: %s", resp.Status)
	}

	faviconData, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	base64Favicon := base64.StdEncoding.EncodeToString(faviconData)
	faviconMimeType := http.DetectContentType(faviconData)

	dataURI := fmt.Sprintf("data:%s;base64,%s", faviconMimeType, base64Favicon)
	return dataURI, nil
}
func replaceTitle(body string, newTitle string) string {
	re := regexp.MustCompile(`(?i)<title>.*?</title>`)
	return re.ReplaceAllString(body, "<title> * "+newTitle+"</title>")
}
