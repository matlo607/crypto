#include "SHA256.hpp"
#include "HashingStrategy.hpp"
#include "utils.hpp"

#include <endian.h>
#include <cstring>

namespace crypto {

    using namespace utils;

    using SHA256hash_uint32 = CryptoHash_uint32<SHA256_HASH_SIZE>;
    using SHA256MsgBlock_uint32 = MsgBlock_uint32<SHA256_MSGBLOCK_SIZE>;
    using SHA256MsgBlock_uint64 = MsgBlock_uint64<SHA256_MSGBLOCK_SIZE>;

    SHA256hashing::SHA256hashing(void) :
        HashingStrategy<SHA256_HASH_SIZE, SHA256_MSGBLOCK_SIZE>(std::make_unique<SHA256hashing::SHA256BlockCipherLike>())
    {
    }

    SHA256hashing::SHA256BlockCipherLike::SHA256BlockCipherLike(void)
        : HashingStrategy<SHA256_HASH_SIZE, SHA256_MSGBLOCK_SIZE>::StrategyBlockCipherLike()
    {
        reset();
    }

    void SHA256hashing::SHA256BlockCipherLike::reset(void)
    {
        memset(m_msgBlock.data(), 0, sizeof(m_msgBlock));
        m_msgBlockIndex = 0;
        m_intermediateHash = {
            0x6a09e667,
            0xbb67ae85,
            0x3c6ef372,
            0xa54ff53a,
            0x510e527f,
            0x9b05688c,
            0x1f83d9ab,
            0x5be0cd19
        };
    }

    SHA256hash SHA256hashing::SHA256BlockCipherLike::getDigest(void)
    {
        SHA256hash digest;

#if __BYTE_ORDER == __LITTLE_ENDIAN
        // write the hash in big endian
        for (uint8_t i = 0; i < m_intermediateHash.size(); ++i) {
            (*reinterpret_cast<SHA256hash_uint32*>(digest.data()))[i] = htobe32(m_intermediateHash[i]);
        }
#else
        memcpy(digest.data(), m_intermediateHash.data(), digest.size());
#endif

        return std::move(digest);
    }

    void SHA256hashing::SHA256BlockCipherLike::setMsgSize(size_t size)
    {
        (*reinterpret_cast<SHA256MsgBlock_uint64*>(m_msgBlock.data())).back() = htobe64(size);
    }

    void SHA256hashing::SHA256BlockCipherLike::process(void)
    {
        auto CH = [](auto x, auto y, auto z) { return (x & y) ^ (~(x) & z); };
        auto MAJ = [](auto x, auto y, auto z) { return (x & y) ^ (x & z) ^ (y & z); };

        auto EP0 = [](auto x) { return rotate_right(x,2) ^ rotate_right(x,13) ^ rotate_right(x,22); };
        auto EP1 = [](auto x) { return rotate_right(x,6) ^ rotate_right(x,11) ^ rotate_right(x,25); };

        auto SIG0 = [](auto x) { return rotate_right(x,7) ^ rotate_right(x,18) ^ (x >> 3); };
        auto SIG1 = [](auto x) { return rotate_right(x,17) ^ rotate_right(x,19) ^ (x >> 10); };

        static std::array<const uint32_t,64> K = {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
            0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
            0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
            0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
            0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
            0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
            0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
            0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        };

        std::array<uint32_t, 64> W; // word sequence
        uint32_t A, B, C, D, E, F, G, H;     // word buffers

        // initialize the first 16 words in the array W
        for (uint8_t t = 0; t < 16; ++t) {
            W[t] = htobe32((*reinterpret_cast<SHA256MsgBlock_uint32*>(m_msgBlock.data()))[t]);
        }

        for (uint8_t t = 16; t < 64; ++t) {
            W[t] = SIG1(W[t - 2]) + W[t - 7] + SIG0(W[t - 15]) + W[t - 16];
        }

        A = m_intermediateHash[0];
        B = m_intermediateHash[1];
        C = m_intermediateHash[2];
        D = m_intermediateHash[3];
        E = m_intermediateHash[4];
        F = m_intermediateHash[5];
        G = m_intermediateHash[6];
        H = m_intermediateHash[7];

        for (uint8_t t = 0; t < 64; ++t) {
            auto T1 = H + EP1(E) + CH(E,F,G) + K[t] + W[t];
            auto T2 = EP0(A) + MAJ(A,B,C);
            H = G;
            G = F;
            F = E;
            E = D + T1;
            D = C;
            C = B;
            B = A;
            A = T1 + T2;
        }

        m_intermediateHash[0] += A;
        m_intermediateHash[1] += B;
        m_intermediateHash[2] += C;
        m_intermediateHash[3] += D;
        m_intermediateHash[4] += E;
        m_intermediateHash[5] += F;
        m_intermediateHash[6] += G;
        m_intermediateHash[7] += H;

        m_msgBlockIndex = 0;
    }

} /* namespace crypto */

