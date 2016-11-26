#include "MD5.hpp"
#include "HashingStrategy.hpp"
#include "utils.hpp"

#include <cstring>
#include <endian.h>

namespace crypto {

using namespace utils;

using MD5hash_uint32 = CryptoHash_uint32<MD5_HASH_SIZE>;
using MD5MsgBlock_uint32 = MsgBlock_uint32<MD5_MSGBLOCK_SIZE>;
using MD5MsgBlock_uint64 = MsgBlock_uint64<MD5_MSGBLOCK_SIZE>;

using HS = HashingStrategy<MD5_HASH_SIZE, MD5_MSGBLOCK_SIZE>;

MD5hashing::MD5hashing(void) :
    HS(std::make_unique<MD5hashing::MD5BlockCipherLike>())
    {
    }

MD5hashing::MD5BlockCipherLike::MD5BlockCipherLike(void)
    : HS::StrategyBlockCipherLike()
{
    reset();
}

void MD5hashing::MD5BlockCipherLike::reset(void)
{
    memset(m_msgBlock.data(), 0, sizeof(m_msgBlock));
    m_msgBlockIndex = 0;
    m_intermediateHash = {
        0x67452301,
        0xEFCDAB89,
        0x98BADCFE,
        0x10325476
    };
}

MD5hash MD5hashing::MD5BlockCipherLike::getDigest(void)
{
    MD5hash digest;

#if __BYTE_ORDER == __BIG_ENDIAN
    // write the hash in little endian
    for (uint8_t i = 0; i < m_intermediateHash.size(); ++i) {
        (*reinterpret_cast<MD5hash_uint32*>(digest.data()))[i] = htole32(m_intermediateHash[i]);
    }
#else
    memcpy(digest.data(), m_intermediateHash.data(), digest.size());
#endif

    return std::move(digest);
}

void MD5hashing::MD5BlockCipherLike::setMsgSize(size_t size)
{
    (*reinterpret_cast<MD5MsgBlock_uint64*>(m_msgBlock.data())).back() = htole64(size);
}

void MD5hashing::MD5BlockCipherLike::process(void)
{
    auto F = [](auto x, auto y, auto z) { return (x & y) | ((~x) & z); };
    auto G = [](auto x, auto y, auto z) { return (x & z) | (y & (~z)); };
    auto H = [](auto x, auto y, auto z) { return x ^ y ^ z; };
    auto I = [](auto x, auto y, auto z) { return y ^ (x | (~z)); };

    auto f = [](auto x) { return x % 16; };
    auto g = [](auto x) { return (5 * x + 1) % 16; };
    auto h = [](auto x) { return (3 * x + 5) % 16; };
    auto i = [](auto x) { return (7 * x) % 16; };

    auto XX = [](auto X, auto &a, auto b, auto c, auto d, auto k, auto w, auto s)
    {
        a += X(b,c,d) + k + w;
        a = rotate_left(a,s);
        a += b;
    };

    //std::array<uint32_t, MD5_MSGBLOCK_SIZE> K;
    //for (uint8_t i = 0; i < MD5_MSGBLOCK_SIZE; ++i) {
    //    K[i] = floor((1 << 32) * abs(sin(i + 1)));
    //}

    static std::array<const uint32_t, MD5_MSGBLOCK_SIZE> K =
    {
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
        0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
        0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
        0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
        0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
        0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
        0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
        0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
        0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
        0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
        0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
        0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
        0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
        0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
    };

    static std::array<const uint8_t, MD5_MSGBLOCK_SIZE / 4> ref_leftshift =
    {
        7, 12, 17, 22,
        5,  9, 14, 20,
        4, 11, 16, 23,
        6, 10, 15, 21,
    };

    auto shift = [](auto x) { return (x / 16) * 4 + (x % 4); };

    std::array<uint32_t,16> W;
    uint32_t A, B, C, D;

    // initialize the first 16 words in the array W
    for (uint8_t t = 0; t < 16; ++t) {
        W[t] = htole32((*reinterpret_cast<MD5MsgBlock_uint32*>(m_msgBlock.data()))[t]);
    }

    A = m_intermediateHash[0];
    B = m_intermediateHash[1];
    C = m_intermediateHash[2];
    D = m_intermediateHash[3];

    for (uint8_t t = 0; t < 16; ++t) {
        XX( F, A, B, C, D, K[t], W[ f(t) ], ref_leftshift[ shift(t) ] );
        auto temp = D;
        D = C;
        C = B;
        B = A;
        A = temp;
    }

    for (uint8_t t = 16; t < 32; ++t) {
        XX( G, A, B, C, D, K[t], W[ g(t) ], ref_leftshift[ shift(t) ] );
        auto temp = D;
        D = C;
        C = B;
        B = A;
        A = temp;
    }

    for (uint8_t t = 32; t < 48; ++t) {
        XX( H, A, B, C, D, K[t], W[ h(t) ], ref_leftshift[ shift(t) ] );
        auto temp = D;
        D = C;
        C = B;
        B = A;
        A = temp;
    }

    for (uint8_t t = 48; t < 64; ++t) {
        XX( I, A, B, C, D, K[t], W[ i(t) ], ref_leftshift[ shift(t) ] );
        auto temp = D;
        D = C;
        C = B;
        B = A;
        A = temp;
    }

    m_intermediateHash[0] += A;
    m_intermediateHash[1] += B;
    m_intermediateHash[2] += C;
    m_intermediateHash[3] += D;

    m_msgBlockIndex = 0;
}

} /* namespace crypto */

