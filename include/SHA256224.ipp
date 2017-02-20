#include "utils.hpp"
#include "endian.hpp"

namespace crypto {

    using namespace utils;

    namespace sha256224_detail {
        template <size_t N>
            using HS = HashingStrategy<SHA256224_TMPHASH_SIZE, N>;
    } /* namespace sha256224_detail */

    template <size_t N_digest>
        SHA256224hashing<N_digest>::SHA256224hashing(std::unique_ptr< typename sha256224_detail::HS<N_digest>::StrategyBlockCipherLike >&& p) :
            sha256224_detail::HS<N_digest>(std::move(p))
    {
    }

    template <size_t N_digest>
        SHA256224hash<N_digest> SHA256224hashing<N_digest>::SHA256224BlockCipherLike::getDigest(void)
        {
            SHA256224hash<N_digest> digest;

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
            using SHA256224hash_uint32 = CryptoHash_uint32<N_digest>;

            auto& dest = *reinterpret_cast<SHA256224hash_uint32*>(digest.data());
            auto& src = *reinterpret_cast<SHA256224hash_uint32*>(this->m_intermediateHash.data());

            // write the hash in big endian
            std::transform(src.cbegin(),
                           src.cend(),
                           dest.begin(),
                           [] (uint32_t n) { return htobe32(n); });
#else
            auto& temporary = *reinterpret_cast<SHA256224hash*>(this->m_intermediateHash.data());

            std::copy(temporary.cbegin(), temporary.cend(), digest.begin());
#endif

            return std::move(digest);
        }

    template <size_t N_digest>
        void SHA256224hashing<N_digest>::SHA256224BlockCipherLike::setMsgSize(size_t size)
        {
            auto& dest = *reinterpret_cast<typename HSBC<N_digest>::MsgBlock_uint64 *>(this->m_msgBlock.data());
            dest.back() = htobe64(size);
        }

    template <size_t N_digest>
        void SHA256224hashing<N_digest>::SHA256224BlockCipherLike::process(void)
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

            auto& msgBlock = *reinterpret_cast<typename HSBC<N_digest>::MsgBlock_uint32 *>(this->m_msgBlock.data());
            std::array<uint32_t, 64> W; // word sequence
            uint32_t A, B, C, D, E, F, G, H; // word buffers

            // initialize the first 16 words in the array W with the message block
            std::transform(msgBlock.cbegin(),
                           msgBlock.cend(),
                           W.begin(),
                           [] (uint32_t n) { return htobe32(n); });

            for (auto t = msgBlock.size(); t < W.size(); ++t) {
                W[t] = SIG1(W[t - 2]) + W[t - 7] + SIG0(W[t - 15]) + W[t - 16];
            }

            A = this->m_intermediateHash[0];
            B = this->m_intermediateHash[1];
            C = this->m_intermediateHash[2];
            D = this->m_intermediateHash[3];
            E = this->m_intermediateHash[4];
            F = this->m_intermediateHash[5];
            G = this->m_intermediateHash[6];
            H = this->m_intermediateHash[7];

            for (auto t = 0U; t < W.size(); ++t) {
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

            this->m_intermediateHash[0] += A;
            this->m_intermediateHash[1] += B;
            this->m_intermediateHash[2] += C;
            this->m_intermediateHash[3] += D;
            this->m_intermediateHash[4] += E;
            this->m_intermediateHash[5] += F;
            this->m_intermediateHash[6] += G;
            this->m_intermediateHash[7] += H;
        }

} /* namespace crypto */

