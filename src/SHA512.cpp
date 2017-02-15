#include "SHA512.hpp"
#include <cstring>

namespace crypto {

    using HS512384 = SHA512384hashing<SHA512_HASH_SIZE>;

    SHA512hashing::SHA512hashing(void) :
        HS512384(std::make_unique<SHA512hashing::SHA512BlockCipherLike>())
    {
    }

    SHA512hashing::SHA512BlockCipherLike::SHA512BlockCipherLike(void)
        : HS512384::SHA512384BlockCipherLike()
    {
        reset();
    }

    void SHA512hashing::SHA512BlockCipherLike::reset(void)
    {
        m_msgBlock.fill(0);
        m_spaceAvailable = m_msgBlock;
        m_intermediateHash = {
            0x6a09e667f3bcc908,
            0xbb67ae8584caa73b,
            0x3c6ef372fe94f82b,
            0xa54ff53a5f1d36f1,
            0x510e527fade682d1,
            0x9b05688c2b3e6c1f,
            0x1f83d9abfb41bd6b,
            0x5be0cd19137e2179
        };
    }

} /* namespace crypto */

