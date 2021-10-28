#include "include/native_crypto/aes_cbc_cipher.h"

#pragma warning(disable : 4267)

// Shuffle 4 32-bit integers.
#define SHUFFLE4_32(x, y, z, w) (w << 6 | z << 4 | y << 2 | x)

void assistKey256_1(__m128i* tmp, __m128i* tmp2) {
    // Duplicate 4th part 4 times.
    *tmp2 = _mm_shuffle_epi32(*tmp2, SHUFFLE4_32(3, 3, 3, 3));

    __m128i tmp3 = _mm_slli_si128(*tmp, 0x4);
    *tmp = _mm_xor_si128(*tmp, tmp3);

    tmp3 = _mm_slli_si128(tmp3, 0x4);
    *tmp = _mm_xor_si128(*tmp, tmp3);

    tmp3 = _mm_slli_si128(tmp3, 0x4);
    *tmp = _mm_xor_si128(*tmp, tmp3);
    *tmp = _mm_xor_si128(*tmp, *tmp2);
}

void assistKey256_2(__m128i* tmp, __m128i* tmp2) {
    __m128i tmp4 = _mm_aeskeygenassist_si128(*tmp, 0x0);

    // Duplicate 3rd part 4 times.
    __m128i tmp3 = _mm_shuffle_epi32(tmp4, SHUFFLE4_32(2, 2, 2, 2));

    tmp4 = _mm_slli_si128(*tmp2, 0x4);

    *tmp2 = _mm_xor_si128(*tmp2, tmp4);
    tmp4 = _mm_slli_si128(tmp4, 0x4);

    *tmp2 = _mm_xor_si128(*tmp2, tmp4);
    tmp4 = _mm_slli_si128(tmp4, 0x4);

    *tmp2 = _mm_xor_si128(*tmp2, tmp4);
    *tmp2 = _mm_xor_si128(*tmp2, tmp3);
}

void expandKey256(uint8_t* key, __m128i* schedule) {
    __m128i* keySchedule = (__m128i*)schedule;

    // Save the first 128 bits of the key as the first one.
    __m128i tmp = _mm_loadu_si128((__m128i*)key);
    keySchedule[0] = tmp;

    // The next 128 bits as the second.
    __m128i tmp3 = _mm_loadu_si128((__m128i*)(key + 16));
    keySchedule[1] = tmp3;

    __m128i tmp2 = _mm_aeskeygenassist_si128(tmp3, 0x01);

    assistKey256_1(&tmp, &tmp2);
    keySchedule[2] = tmp;

    assistKey256_2(&tmp, &tmp3);
    keySchedule[3] = tmp3;

    tmp2 = _mm_aeskeygenassist_si128(tmp3, 0x02);
    assistKey256_1(&tmp, &tmp2);
    keySchedule[4] = tmp;
    assistKey256_2(&tmp, &tmp3);
    keySchedule[5] = tmp3;

    tmp2 = _mm_aeskeygenassist_si128(tmp3, 0x04);
    assistKey256_1(&tmp, &tmp2);
    keySchedule[6] = tmp;
    assistKey256_2(&tmp, &tmp3);
    keySchedule[7] = tmp3;

    tmp2 = _mm_aeskeygenassist_si128(tmp3, 0x08);
    assistKey256_1(&tmp, &tmp2);
    keySchedule[8] = tmp;
    assistKey256_2(&tmp, &tmp3);
    keySchedule[9] = tmp3;

    tmp2 = _mm_aeskeygenassist_si128(tmp3, 0x10);
    assistKey256_1(&tmp, &tmp2);
    keySchedule[10] = tmp;
    assistKey256_2(&tmp, &tmp3);
    keySchedule[11] = tmp3;

    tmp2 = _mm_aeskeygenassist_si128(tmp3, 0x20);
    assistKey256_1(&tmp, &tmp2);
    keySchedule[12] = tmp;
    assistKey256_2(&tmp, &tmp3);
    keySchedule[13] = tmp3;

    tmp2 = _mm_aeskeygenassist_si128(tmp3, 0x40);
    assistKey256_1(&tmp, &tmp2);
    keySchedule[14] = tmp;
}

void print128(uint8_t* input) {
    for (int i = 0; i < 16; i++) {
        uint8_t x = input[i];
        printf("%02x, ", x);
    }

    printf("\n");
}

AesCbcCipher::AesCbcCipher(std::vector<uint8_t> key, uint8_t* iv, bool forEncrption) {
    this->block = _mm_load_si128((__m128i*)iv);
    expandKey256(key.data(), this->keySchedule);

    this->encrypt = forEncrption;
    this->ready = true;
}

AesCbcCipher::~AesCbcCipher() {}

bool AesCbcCipher::isReady() {
    return this->ready;
}

inline __m128i AesCbcCipher::aesEncrypt(__m128i _block) {
    uint8_t round = 0;

    // Whitening step.
    _block = _mm_xor_si128(_block, this->keySchedule[round++]);

    // Apply the AES rounds.
    while (round < 14) {
        _block = _mm_aesenc_si128(_block, this->keySchedule[round++]);
    }

    // And the last.
    return _mm_aesenclast_si128(_block, this->keySchedule[round]);
}

AES_CBC_CIPHER_ERROR AesCbcCipher::process(uint8_t* data, uint32_t size) {
    const int blocks = size / BLOCK_SIZE;

    for (int i = 0; i < blocks; i++) {
        const int offset = i * BLOCK_SIZE;

        // Load data chunk into buffer.
        __m128i buffer = _mm_load_si128((__m128i*)(data + offset));

        // XOR block contents and data buffer into block.
        this->block = _mm_xor_si128(this->block, buffer);

        // Perform aes encryption on block using schedule.
        this->block = aesEncrypt(this->block);

        // Store result into the data.
        _mm_store_si128((__m128i*)(data + offset), this->block);
    }

    return 0;
}