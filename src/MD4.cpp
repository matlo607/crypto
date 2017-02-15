#include "MD4.hpp"
#include "HashingStrategy.hpp"
#include "utils.hpp"

#include <cstring>
#include <endian.h>

namespace crypto {

using namespace utils;

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
    m_msgBlock.fill(0);
    m_spaceAvailable = m_msgBlock;
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
    using MD4hash_uint32 = CryptoHash_uint32<sizeof(MD4hash)>;

    auto& dest = *reinterpret_cast<MD4hash_uint32*>(digest.data());
    auto& src = *reinterpret_cast<MD4hash_uint32*>(this->m_intermediateHash.data());

    // write the hash in little endian
    std::transform(src.cbegin(),
                   src.cend(),
                   dest.begin(),
                   [] (uint32_t n) { return htole32(n); });
#else
    auto& temporary = *reinterpret_cast<MD4hash*>(m_intermediateHash.data());

    std::copy(temporary.begin(), temporary.end(), digest.begin());
#endif

    return std::move(digest);
}

void MD4hashing::MD4BlockCipherLike::setMsgSize(size_t size)
{
    using MB64 = HSBC::MsgBlock_uint64;
    auto& dest = *reinterpret_cast<MB64*>(m_msgBlock.data());
    dest.back() = htole64(size);
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

    static const std::array<uint32_t, 3> K = { 0, 0x5a827999, 0x6ed9eba1 };

    static const std::array<uint8_t, 12> ref_leftshift =
    {
        3, 7, 11, 19,
        3, 5,  9, 13,
        3, 9, 11, 15
    };

    auto shift = [](auto x) { return (x / 16) * 4 + (x % 4); };

    auto& msgBlock = *reinterpret_cast<MsgBlock_uint32*>(m_msgBlock.data());
    MsgBlock_uint32 W;
    uint32_t A, B, C, D;

    // initialize the first 16 words in the array W
    std::transform(msgBlock.begin(),
                   msgBlock.end(),
                   W.begin(),
                   [](uint32_t n) { return htole32(n); });

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
}

} /* namespace crypto */

