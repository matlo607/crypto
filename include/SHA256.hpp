#ifndef _SHA256_HASHING_
#define _SHA256_HASHING_

#include "SHA256224.hpp"

namespace crypto {

#define SHA256_HASH_SIZE      32 // (in bytes)

    using SHA256hash = CryptoHash<SHA256_HASH_SIZE>;

    class SHA256hashing final : public SHA256224hashing<SHA256_HASH_SIZE>
    {
        public:

            SHA256hashing(void);
            virtual ~SHA256hashing() = default;

            SHA256hashing(const SHA256hashing& other) = delete;
            SHA256hashing& operator=(const SHA256hashing& other) = delete;

            SHA256hashing(SHA256hashing&& other) = default;
            SHA256hashing& operator=(SHA256hashing&& other) = default;

        private:

            class SHA256BlockCipherLike final : public SHA256224BlockCipherLike
            {
                public:
                    SHA256BlockCipherLike(void);
                    virtual ~SHA256BlockCipherLike() = default;

                    SHA256BlockCipherLike(const SHA256BlockCipherLike& other) = delete;
                    SHA256BlockCipherLike& operator=(const SHA256BlockCipherLike& other) = delete;

                    SHA256BlockCipherLike(SHA256BlockCipherLike&& other) = default;
                    SHA256BlockCipherLike& operator=(SHA256BlockCipherLike&& other) = default;

                    virtual void reset(void) final override;
            };
    };

} /* namespace crypto */

#endif

