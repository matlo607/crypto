#include "SHA1.hpp"
#include "HashingStrategy.hpp"
#include "utils.hpp"

#include <endian.h>
#include <cstring>

namespace crypto {

using namespace utils;

SHA1hashing::SHA1hashing(void) :
    HS(std::make_unique<SHA1hashing::SHA1BlockCipherLike>())
{
}

SHA1hashing::SHA1BlockCipherLike::SHA1BlockCipherLike(void)
    : HS::StrategyBlockCipherLike()
{
    reset();
}

void SHA1hashing::SHA1BlockCipherLike::reset(void)
{
    m_msgBlock.fill(0);
    m_spaceAvailable = m_msgBlock;
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
    using SHA1hash_uint32 = CryptoHash_uint32<sizeof(SHA1hash)>;

    auto& dest = *reinterpret_cast<SHA1hash_uint32*>(digest.data());

    // write the hash in big endian
    std::transform(m_intermediateHash.cbegin(),
                   m_intermediateHash.cend(),
                   dest.begin(),
                   [] (uint32_t n) { return htobe32(n); });
#else
    auto& temporary = *reinterpret_cast<SHA1hash*>(m_intermediateHash.data());

    std::copy(temporary.cbegin(), temporary.cend(), digest.begin());
#endif

    return std::move(digest);
}

void SHA1hashing::SHA1BlockCipherLike::setMsgSize(size_t size)
{
    using MB64 = typename HSBC::MsgBlock_uint64;
    auto& dest = *reinterpret_cast<MB64*>(m_msgBlock.data());
    dest.back() = htobe64(size);
}

void SHA1hashing::SHA1BlockCipherLike::process(void)
{
    auto f1 = [](auto a, auto b, auto c) { return (a & b) | ((~a) & c); };
    auto f2 = [](auto a, auto b, auto c) { return a ^ b ^ c; };
    auto f3 = [](auto a, auto b, auto c) { return (a & b) | (c & (a | b)); };
    auto f4 = f2;
    std::function<uint32_t(uint32_t,uint32_t,uint32_t)> F[4] = {f1,f2,f3,f4};

    std::array<const uint32_t, 4> K = {
        0x5A827999,
        0x6ED9EBA1,
        0x8F1BBCDC,
        0xCA62C1D6
    }; // Constants defined in SHA-1

    auto& msgBlock = *reinterpret_cast<MsgBlock_uint32*>(m_msgBlock.data());
    std::array<uint32_t, 80> W; // word sequence
    uint32_t A, B, C, D, E;     // word buffers

    // initialize the first 16 words in the array W with the message block
    std::transform(msgBlock.cbegin(),
                   msgBlock.cend(),
                   W.begin(),
                   [] (uint32_t n) { return htobe32(n); });

    for (auto t = msgBlock.size(); t < W.size(); ++t) {
        W[t] = rotate_left(W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16], 1);
    }

    A = m_intermediateHash[0];
    B = m_intermediateHash[1];
    C = m_intermediateHash[2];
    D = m_intermediateHash[3];
    E = m_intermediateHash[4];

    for (auto i = 0; i < 4; ++i) {
        for (auto t = i*W.size()/4; t < (i+1)*W.size()/4; ++t) {
            auto temp = rotate_left(A,5) + F[i](B,C,D) + E + W[t] + K[i];
            E = D;
            D = C;
            C = rotate_left(B,30);
            B = A;
            A = temp;
        }
    }

    m_intermediateHash[0] += A;
    m_intermediateHash[1] += B;
    m_intermediateHash[2] += C;
    m_intermediateHash[3] += D;
    m_intermediateHash[4] += E;
}

} /* namespace crypto */

