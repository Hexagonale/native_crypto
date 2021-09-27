#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include <windows.h>

#define BLOCK_SIZE 16
#define AES_CBC_CIPHER_ERROR uint32_t

class AesCbcCipher {
   public:
    AesCbcCipher(std::vector<uint8_t> key, uint8_t* iv, bool forEncrption);
    ~AesCbcCipher();

    bool isReady();
    AES_CBC_CIPHER_ERROR process(uint8_t* data, uint32_t size);

   private:
    bool ready = false;
    bool encrypt;

    HCRYPTPROV hProv;
    HCRYPTKEY hKey;
};
