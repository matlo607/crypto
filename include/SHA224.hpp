#ifndef _SHA224_HASHING_
#define _SHA224_HASHING_

#include "SHA256224.hpp"

namespace crypto {

#define SHA224_HASH_SIZE      28 // (in bytes)

    using SHA224hash = CryptoHash<SHA224_HASH_SIZE>;

    class SHA224hashing final : public SHA256224hashing<SHA224_HASH_SIZE>
    {
        public:

            SHA224hashing(void);
            virtual ~SHA224hashing() = default;

            SHA224hashing(const SHA224hashing& other) = delete;
            SHA224hashing& operator=(const SHA224hashing& other) = delete;

            SHA224hashing(SHA224hashing&& other) = default;
            SHA224hashing& operator=(SHA224hashing&& other) = default;

        private:

            class SHA224BlockCipherLike final : public SHA256224BlockCipherLike
            {
                public:
                    SHA224BlockCipherLike(void);
                    virtual ~SHA224BlockCipherLike() = default;

                    SHA224BlockCipherLike(const SHA224BlockCipherLike& other) = delete;
                    SHA224BlockCipherLike& operator=(const SHA224BlockCipherLike& other) = delete;

                    SHA224BlockCipherLike(SHA224BlockCipherLike&& other) = default;
                    SHA224BlockCipherLike& operator=(SHA224BlockCipherLike&& other) = default;

                    virtual void reset(void) final override;
            };
    };

} /* namespace crypto */

#endif

