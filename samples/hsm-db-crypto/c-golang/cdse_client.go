// cdse_client.go — Sample CLI client for the CaumeDSE (Caume Data Security Engine) REST API.
//
// CaumeDSE simulates an HSM + encrypted-database + general crypto interface exposed over HTTPS.
// This client covers secrets management, encrypted CSV databases, and the audit-log endpoint.
//
// Usage (one-shot):
//
//	cdse_client -userId user1 -orgId org1 -orgKey secret info
//	cdse_client -userId user1 -orgId org1 -orgKey secret store-secret mykey /path/to/file "my info"
//	cdse_client -userId user1 -orgId org1 -orgKey secret get-secret mykey
//
// Usage (interactive):
//
//	cdse_client -userId user1 -orgId org1 -i
//
// Environment variables: CDSE_USER_ID, CDSE_ORG_ID, CDSE_ORG_KEY, CDSE_SERVER, CDSE_STORAGE
package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/csv"
	"flag"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// CDSEClient holds connection settings and credentials for all API calls.
type CDSEClient struct {
	Server  string // host:port, e.g. "localhost:8443"
	UserID  string
	OrgID   string
	OrgKey  string
	Storage string // logical storage name, e.g. "EngineStorage"
	HTTP    *http.Client
}

// baseURL constructs the HTTPS base URL for this client.
func (c *CDSEClient) baseURL() string {
	return "https://" + c.Server
}

// orgPath returns the path prefix for the current org+storage.
func (c *CDSEClient) orgPath() string {
	return fmt.Sprintf("/organizations/%s/storage/%s", c.OrgID, c.Storage)
}

// commonParams returns the mandatory query parameters for every request.
func (c *CDSEClient) commonParams() url.Values {
	v := url.Values{}
	v.Set("userId", c.UserID)
	v.Set("orgId", c.OrgID)
	v.Set("orgKey", c.OrgKey)
	return v
}

// get performs an authenticated GET request and returns the raw body.
func (c *CDSEClient) get(path string, extra url.Values) ([]byte, error) {
	params := c.commonParams()
	for k, vs := range extra {
		for _, v := range vs {
			params.Add(k, v)
		}
	}
	u := c.baseURL() + path + "?" + params.Encode()
	resp, err := c.HTTP.Get(u)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("GET %s: HTTP %d — %s", path, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return body, nil
}

// del performs an authenticated DELETE request.
func (c *CDSEClient) del(path string) ([]byte, error) {
	params := c.commonParams()
	u := c.baseURL() + path + "?" + params.Encode()
	req, err := http.NewRequest(http.MethodDelete, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("DELETE %s: %w", path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("DELETE %s: HTTP %d — %s", path, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return body, nil
}

// postMultipart performs an authenticated multipart/form-data POST request.
// fields is a map of text fields; filePath is an optional file to attach under "file".
func (c *CDSEClient) postMultipart(path string, fields map[string]string, filePath string, extra url.Values) ([]byte, error) {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)

	// Write credential fields first (required by CaumeDSE).
	for _, k := range []string{"userId", "orgId", "orgKey"} {
		var v string
		switch k {
		case "userId":
			v = c.UserID
		case "orgId":
			v = c.OrgID
		case "orgKey":
			v = c.OrgKey
		}
		if err := mw.WriteField(k, v); err != nil {
			return nil, err
		}
	}

	// Write any additional text fields (e.g. resourceInfo).
	for k, v := range fields {
		if err := mw.WriteField(k, v); err != nil {
			return nil, err
		}
	}

	// Attach the file part if provided.
	if filePath != "" {
		fw, err := mw.CreateFormFile("file", filepath.Base(filePath))
		if err != nil {
			return nil, err
		}
		f, err := os.Open(filePath)
		if err != nil {
			return nil, fmt.Errorf("open %s: %w", filePath, err)
		}
		defer f.Close()
		if _, err := io.Copy(fw, f); err != nil {
			return nil, err
		}
	}

	if err := mw.Close(); err != nil {
		return nil, err
	}

	// Append common params as query string and any caller extras.
	params := c.commonParams()
	for k, vs := range extra {
		for _, v := range vs {
			params.Add(k, v)
		}
	}
	u := c.baseURL() + path + "?" + params.Encode()

	req, err := http.NewRequest(http.MethodPost, u, &buf)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("POST %s: %w", path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("POST %s: HTTP %d — %s", path, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return body, nil
}

// putForm performs an authenticated PUT request with URL-encoded form values.
func (c *CDSEClient) putForm(path string, extra url.Values) ([]byte, error) {
	params := c.commonParams()
	for k, vs := range extra {
		for _, v := range vs {
			params.Add(k, v)
		}
	}
	u := c.baseURL() + path + "?" + params.Encode()
	req, err := http.NewRequest(http.MethodPut, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("PUT %s: %w", path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("PUT %s: HTTP %d — %s", path, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return body, nil
}

// ─── Command implementations ────────────────────────────────────────────────

// cmdInfo prints user/org information.
func (c *CDSEClient) cmdInfo() error {
	path := fmt.Sprintf("/organizations/%s/users/%s", c.OrgID, c.UserID)
	body, err := c.get(path, nil)
	if err != nil {
		return err
	}
	fmt.Println(string(body))
	return nil
}

// cmdListSecrets lists all raw-file documents in the storage.
func (c *CDSEClient) cmdListSecrets() error {
	path := c.orgPath() + "/documentTypes/file.raw/documents"
	body, err := c.get(path, nil)
	if err != nil {
		return err
	}
	fmt.Println(string(body))
	return nil
}

// cmdStoreSecret uploads a local file as an encrypted secret.
// name is the document name; filePath is the local file; resourceInfo is optional metadata.
func (c *CDSEClient) cmdStoreSecret(name, filePath, resourceInfo string) error {
	path := c.orgPath() + "/documentTypes/file.raw/documents/" + url.PathEscape(name)
	fields := map[string]string{}
	if resourceInfo != "" {
		fields["*resourceInfo"] = resourceInfo
	}
	body, err := c.postMultipart(path, fields, filePath, nil)
	if err != nil {
		return err
	}
	fmt.Println(string(body))
	return nil
}

// cmdGetSecret retrieves a secret and writes it to outFile (or stdout if empty).
func (c *CDSEClient) cmdGetSecret(name, outFile string) error {
	path := c.orgPath() + "/documentTypes/file.raw/documents/" + url.PathEscape(name) + "/content"
	body, err := c.get(path, nil)
	if err != nil {
		return err
	}
	if outFile != "" {
		if err := os.WriteFile(outFile, body, 0600); err != nil {
			return fmt.Errorf("write %s: %w", outFile, err)
		}
		fmt.Printf("Secret '%s' saved to %s (%d bytes)\n", name, outFile, len(body))
	} else {
		os.Stdout.Write(body)
	}
	return nil
}

// cmdDeleteSecret deletes a single secret document.
func (c *CDSEClient) cmdDeleteSecret(name string) error {
	path := c.orgPath() + "/documentTypes/file.raw/documents/" + url.PathEscape(name)
	body, err := c.del(path)
	if err != nil {
		return err
	}
	fmt.Println(string(body))
	return nil
}

// cmdDeleteAllSecrets deletes all raw-file documents in the storage.
func (c *CDSEClient) cmdDeleteAllSecrets() error {
	path := c.orgPath() + "/documentTypes/file.raw/documents"
	body, err := c.del(path)
	if err != nil {
		return err
	}
	fmt.Println(string(body))
	return nil
}

// cmdDBList lists all CSV database documents in the storage.
func (c *CDSEClient) cmdDBList() error {
	path := c.orgPath() + "/documentTypes/file.csv/documents"
	body, err := c.get(path, nil)
	if err != nil {
		return err
	}
	fmt.Println(string(body))
	return nil
}

// cmdDBCreate creates a new encrypted CSV database with the given column headers.
// cols is a comma-separated list such as "name,value,notes".
func (c *CDSEClient) cmdDBCreate(name, cols string) error {
	// Build a temporary CSV file containing only the header row.
	tmp, err := os.CreateTemp("", "cdse_db_*.csv")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := fmt.Fprintf(tmp, "%s\n", cols); err != nil {
		tmp.Close()
		return err
	}
	tmp.Close()

	path := c.orgPath() + "/documentTypes/file.csv/documents/" + url.PathEscape(name)
	body, err := c.postMultipart(path, nil, tmp.Name(), nil)
	if err != nil {
		return err
	}
	fmt.Println(string(body))
	return nil
}

// csvRowCount retrieves the CSV document and returns the number of data rows (excluding header).
func (c *CDSEClient) csvRowCount(name string) (int, error) {
	path := c.orgPath() + "/documentTypes/file.csv/documents/" + url.PathEscape(name) + "/content"
	extra := url.Values{"outputType": {"csv"}}
	body, err := c.get(path, extra)
	if err != nil {
		return 0, err
	}
	r := csv.NewReader(bytes.NewReader(body))
	records, err := r.ReadAll()
	if err != nil {
		return 0, fmt.Errorf("parse CSV: %w", err)
	}
	if len(records) == 0 {
		return 0, nil
	}
	// First record is the header; the rest are data rows.
	return len(records) - 1, nil
}

// cmdDBInsert appends a row to the CSV database. kvPairs is a slice of "col=val" strings.
func (c *CDSEClient) cmdDBInsert(name string, kvPairs []string) error {
	count, err := c.csvRowCount(name)
	if err != nil {
		return fmt.Errorf("count rows: %w", err)
	}
	newRow := count + 1

	path := fmt.Sprintf("%s/documentTypes/file.csv/documents/%s/contentRows/%d",
		c.orgPath(), url.PathEscape(name), newRow)

	extra := url.Values{}
	for _, kv := range kvPairs {
		parts := strings.SplitN(kv, "=", 2)
		if len(parts) != 2 {
			return fmt.Errorf("invalid key=value pair: %q", kv)
		}
		extra.Set("["+parts[0]+"]", parts[1])
	}

	body, err := c.postMultipart(path, nil, "", extra)
	if err != nil {
		return err
	}
	fmt.Printf("Inserted row %d\n%s\n", newRow, string(body))
	return nil
}

// cmdDBQuery retrieves all rows, or a specific row, from a CSV database.
func (c *CDSEClient) cmdDBQuery(name string, row int) error {
	extra := url.Values{"outputType": {"csv"}}
	var path string
	if row > 0 {
		path = fmt.Sprintf("%s/documentTypes/file.csv/documents/%s/contentRows/%d",
			c.orgPath(), url.PathEscape(name), row)
	} else {
		path = c.orgPath() + "/documentTypes/file.csv/documents/" + url.PathEscape(name) + "/content"
	}
	body, err := c.get(path, extra)
	if err != nil {
		return err
	}
	fmt.Print(string(body))
	return nil
}

// cmdDBUpdate updates a specific row in a CSV database.
func (c *CDSEClient) cmdDBUpdate(name string, row int, kvPairs []string) error {
	path := fmt.Sprintf("%s/documentTypes/file.csv/documents/%s/contentRows/%d",
		c.orgPath(), url.PathEscape(name), row)

	extra := url.Values{}
	for _, kv := range kvPairs {
		parts := strings.SplitN(kv, "=", 2)
		if len(parts) != 2 {
			return fmt.Errorf("invalid key=value pair: %q", kv)
		}
		extra.Set("["+parts[0]+"]", parts[1])
	}

	body, err := c.putForm(path, extra)
	if err != nil {
		return err
	}
	fmt.Println(string(body))
	return nil
}

// cmdDBDeleteRow deletes a specific row from a CSV database.
func (c *CDSEClient) cmdDBDeleteRow(name string, row int) error {
	path := fmt.Sprintf("%s/documentTypes/file.csv/documents/%s/contentRows/%d",
		c.orgPath(), url.PathEscape(name), row)
	body, err := c.del(path)
	if err != nil {
		return err
	}
	fmt.Println(string(body))
	return nil
}

// cmdDBDelete deletes an entire CSV database document.
func (c *CDSEClient) cmdDBDelete(name string) error {
	path := c.orgPath() + "/documentTypes/file.csv/documents/" + url.PathEscape(name)
	body, err := c.del(path)
	if err != nil {
		return err
	}
	fmt.Println(string(body))
	return nil
}

// cmdAuditLog retrieves the transaction/audit log and prints it as CSV.
func (c *CDSEClient) cmdAuditLog() error {
	extra := url.Values{"outputType": {"csv"}}
	body, err := c.get("/transactions", extra)
	if err != nil {
		return err
	}
	fmt.Print(string(body))
	return nil
}

// ─── Help ───────────────────────────────────────────────────────────────────

func printHelp() {
	fmt.Print(`cdse_client — CaumeDSE REST API CLI

USAGE
  cdse_client [FLAGS] COMMAND [ARGS...]

FLAGS
  -server   <host:port>   CaumeDSE server (default: localhost:8443)
  -userId   <id>          User ID            (env: CDSE_USER_ID)
  -orgId    <id>          Organisation ID    (env: CDSE_ORG_ID)
  -orgKey   <key>         Organisation key   (env: CDSE_ORG_KEY)
  -storage  <name>        Storage name       (env: CDSE_STORAGE, default: EngineStorage)
  -insecure               Skip TLS certificate verification
  -ca-cert  <path>        Path to custom CA certificate (PEM)
  -i                      Interactive mode (prompt for credentials once, then loop)

COMMANDS
  info                              Show user/org info
  list-secrets                      List all raw-file secrets
  store-secret  NAME FILE [INFO]    Upload FILE as secret NAME (INFO = optional metadata)
  get-secret    NAME [OUTFILE]      Download secret (write to OUTFILE or stdout)
  delete-secret NAME                Delete a single secret
  db-list                           List CSV databases
  db-create     NAME col1,col2,...  Create CSV database with given columns
  db-insert     NAME col=val ...    Append a row (key=value pairs)
  db-query      NAME [ROW]          Get all rows or specific row number
  db-update     NAME ROW col=val .. Update a row
  db-delete-row NAME ROW            Delete a row
  db-delete     NAME                Delete an entire CSV database
  audit-log                         Print the audit / transaction log (CSV)
  help                              Show this help

EXAMPLES
  # One-shot: store a secret, retrieve it, then delete it
  cdse_client -userId alice -orgId acme -orgKey s3cr3t \
      store-secret mypassword /etc/passwd "system passwords"
  cdse_client -userId alice -orgId acme -orgKey s3cr3t get-secret mypassword
  cdse_client -userId alice -orgId acme -orgKey s3cr3t delete-secret mypassword

  # One-shot: create a CSV DB, insert and query rows
  cdse_client -userId alice -orgId acme -orgKey s3cr3t \
      db-create tokens id,token,label
  cdse_client -userId alice -orgId acme -orgKey s3cr3t \
      db-insert tokens id=1 token=abc123 label=dev
  cdse_client -userId alice -orgId acme -orgKey s3cr3t db-query tokens

  # Interactive mode (org key entered without echo)
  cdse_client -userId alice -orgId acme -i

  # Using environment variables
  export CDSE_USER_ID=alice CDSE_ORG_ID=acme CDSE_ORG_KEY=s3cr3t
  cdse_client audit-log
`)
}

// ─── Credential helpers ─────────────────────────────────────────────────────

// envOr returns the value of env variable key, or fallback if the variable is unset/empty.
func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// readPasswordNoEcho prints prompt and reads a line with terminal echo suppressed.
// Falls back to normal ReadString if stty is unavailable (e.g. non-TTY).
func readPasswordNoEcho(prompt string) (string, error) {
	fmt.Print(prompt)

	// Attempt to disable echo via stty (Linux/macOS).
	disableEcho := exec.Command("stty", "-echo")
	disableEcho.Stdin = os.Stdin
	if err := disableEcho.Run(); err == nil {
		// Re-enable echo when done, even on error.
		defer func() {
			enableEcho := exec.Command("stty", "echo")
			enableEcho.Stdin = os.Stdin
			_ = enableEcho.Run()
			fmt.Println() // newline after hidden input
		}()
	}

	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// ─── Interactive mode ────────────────────────────────────────────────────────

// runInteractive prompts for any missing credentials then enters a REPL loop.
func runInteractive(client *CDSEClient) {
	reader := bufio.NewReader(os.Stdin)

	if client.UserID == "" {
		fmt.Print("userId: ")
		line, _ := reader.ReadString('\n')
		client.UserID = strings.TrimRight(line, "\r\n")
	}
	if client.OrgID == "" {
		fmt.Print("orgId: ")
		line, _ := reader.ReadString('\n')
		client.OrgID = strings.TrimRight(line, "\r\n")
	}
	if client.OrgKey == "" {
		key, err := readPasswordNoEcho("orgKey: ")
		if err != nil {
			fmt.Fprintln(os.Stderr, "Error reading orgKey:", err)
			os.Exit(1)
		}
		client.OrgKey = key
	}

	fmt.Printf("Connected to %s  org=%s  user=%s  storage=%s\n",
		client.Server, client.OrgID, client.UserID, client.Storage)

	for {
		fmt.Print("cdse> ")
		line, err := reader.ReadString('\n')
		if err != nil {
			// EOF (Ctrl-D) — clean exit.
			fmt.Println()
			break
		}
		line = strings.TrimRight(line, "\r\n")
		args := strings.Fields(line)
		if len(args) == 0 {
			continue
		}
		if args[0] == "exit" || args[0] == "quit" {
			break
		}
		if err := dispatch(client, args); err != nil {
			fmt.Fprintln(os.Stderr, "Error:", err)
		}
	}
}

// ─── Dispatcher ─────────────────────────────────────────────────────────────

// dispatch routes a command (slice of strings starting with the verb) to the
// appropriate CDSEClient method.
func dispatch(c *CDSEClient, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("no command provided; run 'help' for usage")
	}
	cmd := args[0]
	rest := args[1:]

	switch cmd {
	case "help":
		printHelp()

	case "info":
		return c.cmdInfo()

	case "list-secrets":
		return c.cmdListSecrets()

	case "store-secret":
		if len(rest) < 2 {
			return fmt.Errorf("store-secret requires NAME and FILE")
		}
		info := ""
		if len(rest) >= 3 {
			info = rest[2]
		}
		return c.cmdStoreSecret(rest[0], rest[1], info)

	case "get-secret":
		if len(rest) < 1 {
			return fmt.Errorf("get-secret requires NAME")
		}
		outFile := ""
		if len(rest) >= 2 {
			outFile = rest[1]
		}
		return c.cmdGetSecret(rest[0], outFile)

	case "delete-secret":
		if len(rest) < 1 {
			return fmt.Errorf("delete-secret requires NAME")
		}
		return c.cmdDeleteSecret(rest[0])

	case "db-list":
		return c.cmdDBList()

	case "db-create":
		if len(rest) < 2 {
			return fmt.Errorf("db-create requires NAME and col1,col2,...")
		}
		return c.cmdDBCreate(rest[0], rest[1])

	case "db-insert":
		if len(rest) < 2 {
			return fmt.Errorf("db-insert requires NAME and at least one col=val pair")
		}
		return c.cmdDBInsert(rest[0], rest[1:])

	case "db-query":
		if len(rest) < 1 {
			return fmt.Errorf("db-query requires NAME")
		}
		row := 0
		if len(rest) >= 2 {
			n, err := strconv.Atoi(rest[1])
			if err != nil {
				return fmt.Errorf("ROW must be an integer: %w", err)
			}
			row = n
		}
		return c.cmdDBQuery(rest[0], row)

	case "db-update":
		if len(rest) < 3 {
			return fmt.Errorf("db-update requires NAME ROW col=val ...")
		}
		row, err := strconv.Atoi(rest[1])
		if err != nil {
			return fmt.Errorf("ROW must be an integer: %w", err)
		}
		return c.cmdDBUpdate(rest[0], row, rest[2:])

	case "db-delete-row":
		if len(rest) < 2 {
			return fmt.Errorf("db-delete-row requires NAME and ROW")
		}
		row, err := strconv.Atoi(rest[1])
		if err != nil {
			return fmt.Errorf("ROW must be an integer: %w", err)
		}
		return c.cmdDBDeleteRow(rest[0], row)

	case "db-delete":
		if len(rest) < 1 {
			return fmt.Errorf("db-delete requires NAME")
		}
		return c.cmdDBDelete(rest[0])

	case "audit-log":
		return c.cmdAuditLog()

	default:
		return fmt.Errorf("unknown command %q — run 'help' for usage", cmd)
	}
	return nil
}

// ─── main ────────────────────────────────────────────────────────────────────

func main() {
	// ── Flag definitions ──────────────────────────────────────────────────
	serverFlag := flag.String("server", envOr("CDSE_SERVER", "localhost:8443"), "CaumeDSE host:port")
	userFlag := flag.String("userId", envOr("CDSE_USER_ID", ""), "User ID")
	orgFlag := flag.String("orgId", envOr("CDSE_ORG_ID", ""), "Organisation ID")
	keyFlag := flag.String("orgKey", envOr("CDSE_ORG_KEY", ""), "Organisation encryption key")
	storageFlag := flag.String("storage", envOr("CDSE_STORAGE", "EngineStorage"), "Storage name")
	insecureFlag := flag.Bool("insecure", false, "Skip TLS certificate verification")
	caCertFlag := flag.String("ca-cert", "", "Path to CA certificate (PEM)")
	interactiveFlag := flag.Bool("i", false, "Interactive mode")

	flag.Usage = func() { printHelp() }
	flag.Parse()

	// ── Build HTTP client ─────────────────────────────────────────────────
	tlsCfg := &tls.Config{}

	if *insecureFlag {
		tlsCfg.InsecureSkipVerify = true //nolint:gosec // intentional dev-mode flag
	} else if *caCertFlag != "" {
		pem, err := os.ReadFile(*caCertFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading CA cert %s: %v\n", *caCertFlag, err)
			os.Exit(1)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			fmt.Fprintln(os.Stderr, "Error: no valid certificates found in CA cert file")
			os.Exit(1)
		}
		tlsCfg.RootCAs = pool
	}

	httpClient := &http.Client{
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
	}

	// ── Build CDSEClient ──────────────────────────────────────────────────
	client := &CDSEClient{
		Server:  *serverFlag,
		UserID:  *userFlag,
		OrgID:   *orgFlag,
		OrgKey:  *keyFlag,
		Storage: *storageFlag,
		HTTP:    httpClient,
	}

	// ── Dispatch ──────────────────────────────────────────────────────────
	if *interactiveFlag {
		runInteractive(client)
		return
	}

	// One-shot mode: command comes from positional arguments.
	args := flag.Args()
	if len(args) == 0 {
		printHelp()
		os.Exit(0)
	}

	// Ensure credentials are present for non-help commands.
	if args[0] != "help" {
		if client.UserID == "" || client.OrgID == "" || client.OrgKey == "" {
			fmt.Fprintln(os.Stderr,
				"Error: -userId, -orgId, and -orgKey (or CDSE_USER_ID/CDSE_ORG_ID/CDSE_ORG_KEY) are required")
			os.Exit(1)
		}
	}

	if err := dispatch(client, args); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}
