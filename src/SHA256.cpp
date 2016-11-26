#include "SHA256.hpp"
#include <cstring>

namespace crypto {

    using HS256224 = SHA256224hashing<SHA256_HASH_SIZE>;

    SHA256hashing::SHA256hashing(void) :
        HS256224(std::make_unique<SHA256hashing::SHA256BlockCipherLike>())
    {
    }

    SHA256hashing::SHA256BlockCipherLike::SHA256BlockCipherLike(void)
        : HS256224::SHA256224BlockCipherLike()
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

} /* namespace crypto */

