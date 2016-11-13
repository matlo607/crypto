#include "SHA1.hpp"
#include "HashingStrategy.hpp"
#include "utils.hpp"

#include <endian.h>
#include <cstring>

namespace crypto {

using namespace utils;

using SHA1hash_uint32 = CryptoHash_uint32<SHA1_HASH_SIZE>;
using SHA1MsgBlock_uint32 = MsgBlock_uint32<SHA1_MSGBLOCK_SIZE>;
using SHA1MsgBlock_uint64 = MsgBlock_uint64<SHA1_MSGBLOCK_SIZE>;

SHA1hashing::SHA1hashing(void) :
    HashingStrategy<SHA1_HASH_SIZE, SHA1_MSGBLOCK_SIZE>(std::make_unique<SHA1hashing::SHA1BlockCipherLike>())
    {
    }

SHA1hashing::SHA1BlockCipherLike::SHA1BlockCipherLike(void)
    : HashingStrategy<SHA1_HASH_SIZE, SHA1_MSGBLOCK_SIZE>::StrategyBlockCipherLike()
{
    reset();
}

void SHA1hashing::SHA1BlockCipherLike::reset(void)
{
    memset(m_msgBlock.data(), 0, sizeof(m_msgBlock));
    m_msgBlockIndex = 0;
    m_intermediateHash = {
        0x67452301,
        0xEFCDAB89,
        0x98BADCFE,
        0x10325476,
        0xC3D2E1F0
    };
}

SHA1hash SHA1hashing::SHA1BlockCipherLike::getDigest(void)
{
    SHA1hash digest;

#if __BYTE_ORDER == __LITTLE_ENDIAN
    // write the hash in big endian
    for (uint8_t i = 0; i < m_intermediateHash.size(); ++i) {
        (*reinterpret_cast<SHA1hash_uint32*>(digest.data()))[i] = htobe32(m_intermediateHash[i]);
    }
#else
    memcpy(digest.data(), m_intermediateHash.data(), digest.size());
#endif

    return std::move(digest);
}

void SHA1hashing::SHA1BlockCipherLike::setMsgSize(size_t size)
{
    (*reinterpret_cast<SHA1MsgBlock_uint64*>(m_msgBlock.data())).back() = htobe64(size);
}

void SHA1hashing::SHA1BlockCipherLike::process(void)
{
    auto f1 = [](auto a, auto b, auto c) { return (a & b) | ((~a) & c); };
    auto f2 = [](auto a, auto b, auto c) { return a ^ b ^ c; };
    auto f3 = [](auto a, auto b, auto c) { return (a & b) | (c & (a | b)); };
    auto f4 = f2;

    std::array<const uint32_t, 4> K = {
        0x5A827999,
        0x6ED9EBA1,
        0x8F1BBCDC,
        0xCA62C1D6
    }; // Constants defined in SHA-1

    std::array<uint32_t, 80> W; // word sequence
    uint32_t A, B, C, D, E;     // word buffers

    // initialize the first 16 words in the array W
    for (uint8_t t = 0; t < 16; ++t) {
        W[t] = htobe32((*reinterpret_cast<SHA1MsgBlock_uint32*>(m_msgBlock.data()))[t]);
    }

    for (uint8_t t = 16; t < 80; ++t) {
        W[t] = rotate_left(W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16], 1);
    }

    A = m_intermediateHash[0];
    B = m_intermediateHash[1];
    C = m_intermediateHash[2];
    D = m_intermediateHash[3];
    E = m_intermediateHash[4];

    for (uint8_t t = 0; t < 20; ++t) {
        auto temp = rotate_left(A,5) + f1(B,C,D) + E + W[t] + K[0];
        E = D;
        D = C;
        C = rotate_left(B,30);
        B = A;
        A = temp;
    }

    for(uint8_t t = 20; t < 40; ++t) {
        auto temp = rotate_left(A,5) + f2(B,C,D) + E + W[t] + K[1];
        E = D;
        D = C;
        C = rotate_left(B,30);
        B = A;
        A = temp;
    }

    for(uint8_t t = 40; t < 60; ++t) {
        auto temp = rotate_left(A,5) + f3(B,C,D) + E + W[t] + K[2];
        E = D;
        D = C;
        C = rotate_left(B,30);
        B = A;
        A = temp;
    }

    for(uint8_t t = 60; t < 80; ++t) {
        auto temp = rotate_left(A,5) + f4(B,C,D) + E + W[t] + K[3];
        E = D;
        D = C;
        C = rotate_left(B,30);
        B = A;
        A = temp;
    }

    m_intermediateHash[0] += A;
    m_intermediateHash[1] += B;
    m_intermediateHash[2] += C;
    m_intermediateHash[3] += D;
    m_intermediateHash[4] += E;

    m_msgBlockIndex = 0;
}

} /* namespace crypto */

