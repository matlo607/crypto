#include "utils.hpp"

#include <endian.h>
#include <cstring>

namespace crypto {

    using namespace utils;

    namespace sha512384_detail {
        template <size_t N>
            using HS = HashingStrategy<SHA512384_TMPHASH_SIZE, N, uint64_t>;
    } /* namespace sha512384_detail */

    template <size_t N_digest>
        SHA512384hashing<N_digest>::SHA512384hashing(std::unique_ptr< typename sha512384_detail::HS<N_digest>::StrategyBlockCipherLike >&& p) :
            sha512384_detail::HS<N_digest>(std::move(p))
    {
    }

    template <size_t N_digest>
        SHA512384hash<N_digest> SHA512384hashing<N_digest>::SHA512384BlockCipherLike::getDigest(void)
        {
            SHA512384hash<N_digest> digest;

#if __BYTE_ORDER == __LITTLE_ENDIAN
            using SHA512384hash_uint64 = CryptoHash_uint64<N_digest>;

            auto& dest = *reinterpret_cast<SHA512384hash_uint64*>(digest.data());
            auto& src = *reinterpret_cast<SHA512384hash_uint64*>(this->m_intermediateHash.data());

            // write the hash in big endian
            std::transform(src.cbegin(),
                           src.cend(),
                           dest.begin(),
                           [] (uint64_t n) { return htobe64(n); });
#else
            auto& temporary = *reinterpret_cast<SHA512384hash*>(this->m_intermediateHash.data());

            std::copy(temporary.cbegin(), temporary.cend(), digest.begin());
#endif

            return std::move(digest);
        }

    template <size_t N_digest>
        void SHA512384hashing<N_digest>::SHA512384BlockCipherLike::setMsgSize(size_t size)
        {
            using MB64 = typename HSBC<N_digest>::MsgBlock_uint64;
            auto it = (*reinterpret_cast<MB64*>(this->m_msgBlock.data())).end();
            *--it = htobe64(size);
            *--it = 0; // assume that a file with a size greater than 2^61 bytes does not exist for now
        }

    template <size_t N_digest>
        void SHA512384hashing<N_digest>::SHA512384BlockCipherLike::process(void)
        {
            auto F0 = [](auto x, auto y, auto z) { return (x & y) | (z & (x | y)); };
            auto F1 = [](auto x, auto y, auto z) { return z ^ (x & (y ^ z)); };

            auto EP0 = [](uint64_t x) { return rotate_right(x,28) ^ rotate_right(x,34) ^ rotate_right(x,39); };
            auto EP1 = [](uint64_t x) { return rotate_right(x,14) ^ rotate_right(x,18) ^ rotate_right(x,41); };

            auto SIG0 = [](uint64_t x) { return rotate_right(x,1) ^ rotate_right(x,8) ^ (x >> 7); };
            auto SIG1 = [](uint64_t x) { return rotate_right(x,19) ^ rotate_right(x,61) ^ (x >> 6); };

            static std::array<const uint64_t,80> K = {
                0x428a2f98d728ae22, 0x7137449123ef65cd,
                0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
                0x3956c25bf348b538, 0x59f111f1b605d019,
                0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
                0xd807aa98a3030242, 0x12835b0145706fbe,
                0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
                0x72be5d74f27b896f, 0x80deb1fe3b1696b1,
                0x9bdc06a725c71235, 0xc19bf174cf692694,
                0xe49b69c19ef14ad2, 0xefbe4786384f25e3,
                0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
                0x2de92c6f592b0275, 0x4a7484aa6ea6e483,
                0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
                0x983e5152ee66dfab, 0xa831c66d2db43210,
                0xb00327c898fb213f, 0xbf597fc7beef0ee4,
                0xc6e00bf33da88fc2, 0xd5a79147930aa725,
                0x06ca6351e003826f, 0x142929670a0e6e70,
                0x27b70a8546d22ffc, 0x2e1b21385c26c926,
                0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
                0x650a73548baf63de, 0x766a0abb3c77b2a8,
                0x81c2c92e47edaee6, 0x92722c851482353b,
                0xa2bfe8a14cf10364, 0xa81a664bbc423001,
                0xc24b8b70d0f89791, 0xc76c51a30654be30,
                0xd192e819d6ef5218, 0xd69906245565a910,
                0xf40e35855771202a, 0x106aa07032bbd1b8,
                0x19a4c116b8d2d0c8, 0x1e376c085141ab53,
                0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
                0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb,
                0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
                0x748f82ee5defb2fc, 0x78a5636f43172f60,
                0x84c87814a1f0ab72, 0x8cc702081a6439ec,
                0x90befffa23631e28, 0xa4506cebde82bde9,
                0xbef9a3f7b2c67915, 0xc67178f2e372532b,
                0xca273eceea26619c, 0xd186b8c721c0c207,
                0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
                0x06f067aa72176fba, 0x0a637dc5a2c898a6,
                0x113f9804bef90dae, 0x1b710b35131c471b,
                0x28db77f523047d84, 0x32caab7b40c72493,
                0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
                0x4cc5d4becb3e42b6, 0x597f299cfc657e2a,
                0x5fcb6fab3ad6faec, 0x6c44198c4a475817
            };

            auto& msgBlock = *reinterpret_cast<typename HSBC<N_digest>::MsgBlock_uint64 *>(this->m_msgBlock.data());
            std::array<uint64_t, 80> W; // word sequence
            uint64_t A, B, C, D, E, F, G, H; // word buffers

            // initialize the first 16 words in the array W with the message block
            std::transform(msgBlock.cbegin(),
                           msgBlock.cend(),
                           W.begin(),
                           [] (uint64_t n) { return htobe64(n); });

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
                auto T1 = H + EP1(E) + F1(E,F,G) + K[t] + W[t];
                auto T2 = EP0(A) + F0(A,B,C);
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

