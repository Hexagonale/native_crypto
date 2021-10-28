#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include <windows.h>

#include <immintrin.h>

#pragma warning(disable : 4324)

#define BLOCK_SIZE 16
#define AES_CBC_CIPHER_ERROR uint32_t

class AesCbcCipher {
   public:
    AesCbcCipher(std::vector<uint8_t> key, uint8_t* iv, bool forEncrption);
    ~AesCbcCipher();

    bool isReady();
    AES_CBC_CIPHER_ERROR process(uint8_t* data, uint32_t size);

   private:
    inline __m128i aesEncrypt(__m128i block);

    bool ready = false;
    bool encrypt;

    __m128i keySchedule[15];
    __m128i block;
};
