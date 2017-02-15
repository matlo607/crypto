#include "SHA384.hpp"
#include <cstring>

namespace crypto {

    using HS512384 = SHA512384hashing<SHA384_HASH_SIZE>;

    SHA384hashing::SHA384hashing(void) :
        HS512384(std::make_unique<SHA384hashing::SHA384BlockCipherLike>())
    {
    }

    SHA384hashing::SHA384BlockCipherLike::SHA384BlockCipherLike(void)
        : HS512384::SHA512384BlockCipherLike()
    {
        reset();
    }

    void SHA384hashing::SHA384BlockCipherLike::reset(void)
    {
        m_msgBlock.fill(0);
        m_spaceAvailable = m_msgBlock;
        m_intermediateHash = {
            0xcbbb9d5dc1059ed8,
            0x629a292a367cd507,
            0x9159015a3070dd17,
            0x152fecd8f70e5939,
            0x67332667ffc00b31,
            0x8eb44a8768581511,
            0xdb0c2e0d64f98fa7,
            0x47b5481dbefa4fa4
        };
    }

} /* namespace crypto */

