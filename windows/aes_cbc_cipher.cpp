#include "include/native_crypto/aes_cbc_cipher.h"

#pragma warning(disable : 4267)
bool _deriveKey(HCRYPTPROV hProv, HCRYPTKEY* hKey, std::vector<uint8_t> input) {
    HCRYPTHASH hHash;

    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        printf("Error creating hash: %x\n", GetLastError());
        return false;
    }

    DWORD keyLen = input.size();
    if (!CryptHashData(hHash, input.data(), keyLen, 0)) {
        printf("Error hashing: %x\n", GetLastError());
        CryptDestroyHash(hHash);
        return false;
    }

    // _printHash(hHash);

    if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, hKey)) {
        CryptDestroyHash(hHash);
        return false;
    }

    return true;
}

AesCbcCipher::AesCbcCipher(std::vector<uint8_t> key, uint8_t* iv, bool forEncrption) {
    wchar_t info[] = L"Microsoft Enhanced RSA and AES Cryptographic Provider";

    // Acquire cryptography context.
    if (!CryptAcquireContextW(&this->hProv, NULL, info, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        CryptReleaseContext(this->hProv, 0);
        return;
    }

    // Create derived key.
    if (!_deriveKey(this->hProv, &this->hKey, key)) {
        CryptReleaseContext(this->hProv, 0);
        return;
    }

    // Set init vector.
    if (!CryptSetKeyParam(this->hKey, KP_IV, iv, 0)) {
        CryptReleaseContext(this->hProv, 0);
        CryptDestroyKey(this->hKey);
        return;
    }

    this->encrypt = forEncrption;
    this->ready = true;
}

AesCbcCipher::~AesCbcCipher() {
    CryptReleaseContext(this->hProv, 0);
    CryptDestroyKey(this->hKey);
}

bool AesCbcCipher::isReady() {
    return this->ready;
}

AES_CBC_CIPHER_ERROR AesCbcCipher::process(uint8_t* data, uint32_t size) {
    DWORD length = BLOCK_SIZE;
    const int blocks = size / BLOCK_SIZE;

    for (int i = 0; i < blocks; i++) {
        const int offset = i * BLOCK_SIZE;

        if (!CryptEncrypt(this->hKey, NULL, false, 0, data + offset, &length, BLOCK_SIZE)) {
            DWORD error = GetLastError();
            printf("Error encrypting: %d (0x%x)\n", error, error);

            return 1;
        }
    }

    return 0;
}