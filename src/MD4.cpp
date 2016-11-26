#include "MD4.hpp"
#include "HashingStrategy.hpp"
#include "utils.hpp"

#include <cstring>
#include <endian.h>

namespace crypto {

using namespace utils;

using MD4hash_uint32 = CryptoHash_uint32<MD4_HASH_SIZE>;
using MD4MsgBlock_uint32 = MsgBlock_uint32<MD4_MSGBLOCK_SIZE>;
using MD4MsgBlock_uint64 = MsgBlock_uint64<MD4_MSGBLOCK_SIZE>;

using HS = HashingStrategy<MD4_HASH_SIZE, uint32_t, MD4_MSGBLOCK_SIZE>;

MD4hashing::MD4hashing(void) :
    HS(std::make_unique<MD4hashing::MD4BlockCipherLike>())
    {
    }

MD4hashing::MD4BlockCipherLike::MD4BlockCipherLike(void)
    : HS::StrategyBlockCipherLike()
{
    reset();
}

void MD4hashing::MD4BlockCipherLike::reset(void)
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

MD4hash MD4hashing::MD4BlockCipherLike::getDigest(void)
{
    MD4hash digest;

#if __BYTE_ORDER == __BIG_ENDIAN
    // write the hash in little endian
    for (uint8_t i = 0; i < m_intermediateHash.size(); ++i) {
        (*reinterpret_cast<MD4hash_uint32*>(digest.data()))[i] = htole32(m_intermediateHash[i]);
    }
#else
    memcpy(digest.data(), m_intermediateHash.data(), digest.size());
#endif

    return std::move(digest);
}

void MD4hashing::MD4BlockCipherLike::setMsgSize(size_t size)
{
    (*reinterpret_cast<MD4MsgBlock_uint64*>(m_msgBlock.data())).back() = htole64(size);
}

void MD4hashing::MD4BlockCipherLike::process(void)
{
    auto F = [](auto x, auto y, auto z) { return (x & y) | ((~x) & z); };
    auto G = [](auto x, auto y, auto z) { return (x & (y | z)) | (y & z); };
    auto H = [](auto x, auto y, auto z) { return x ^ y ^ z; };

#define mod16(x) ((x) % 16)
#define div4(x) (mod16(x) / 4)

    auto f = [](auto x) { return mod16(x); };
    auto g = [](auto x) { return div4(x) + (x % 4) * 4; };
    auto h = [](auto x) {
        auto h1 = [] (auto x) { return (x % 2) * 2 + (x % 4) / 2; };
        return h1(x) * 4 + h1( div4(x) );
    };

    auto XX = [](auto X, auto &a, auto b, auto c, auto d, auto k, auto w, auto s)
    {
        a += X(b,c,d) + w + k;
        a = rotate_left(a,s);
    };

    static std::array<const uint32_t, 3> K = { 0, 0x5a827999, 0x6ed9eba1 };

    static std::array<const uint8_t, 12> ref_leftshift =
    {
        3, 7, 11, 19,
        3, 5,  9, 13,
        3, 9, 11, 15
    };

    auto shift = [](auto x) { return (x / 16) * 4 + (x % 4); };

    std::array<uint32_t,16> W;
    uint32_t A, B, C, D;

    // initialize the first 16 words in the array W
    for (uint8_t t = 0; t < 16; ++t) {
        W[t] = htole32((*reinterpret_cast<MD4MsgBlock_uint32*>(m_msgBlock.data()))[t]);
    }

    A = m_intermediateHash[0];
    B = m_intermediateHash[1];
    C = m_intermediateHash[2];
    D = m_intermediateHash[3];

    for (uint8_t t = 0; t < 16; ++t) {
        XX( F, A, B, C, D, K[t/16], W[ f(t) ], ref_leftshift[ shift(t) ] );
        auto temp = D;
        D = C;
        C = B;
        B = A;
        A = temp;
    }

    for (uint8_t t = 16; t < 32; ++t) {
        XX( G, A, B, C, D, K[t/16], W[ g(t) ], ref_leftshift[ shift(t) ] );
        auto temp = D;
        D = C;
        C = B;
        B = A;
        A = temp;
    }

    for (uint8_t t = 32; t < 48; ++t) {
        XX( H, A, B, C, D, K[t/16], W[ h(t) ], ref_leftshift[ shift(t) ] );
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

