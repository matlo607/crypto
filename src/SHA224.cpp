#include "SHA224.hpp"
#include <cstring>

namespace crypto {

    using HS256224 = SHA256224hashing<SHA224_HASH_SIZE>;

    SHA224hashing::SHA224hashing(void) :
        HS256224(std::make_unique<SHA224hashing::SHA224BlockCipherLike>())
    {
    }

    SHA224hashing::SHA224BlockCipherLike::SHA224BlockCipherLike(void)
        : HS256224::SHA256224BlockCipherLike::SHA256224BlockCipherLike()
    {
        reset();
    }

    void SHA224hashing::SHA224BlockCipherLike::reset(void)
    {
        memset(m_msgBlock.data(), 0, sizeof(m_msgBlock));
        m_msgBlockIndex = 0;
        m_intermediateHash = {
            0xc1059ed8,
            0x367cd507,
            0x3070dd17,
            0xf70e5939,
            0xffc00b31,
            0x68581511,
            0x64f98fa7,
            0xbefa4fa4
        };
    }

} /* namespace crypto */

