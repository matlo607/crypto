#ifndef _SHA512_HASHING_
#define _SHA512_HASHING_

#include "SHA512384.hpp"

namespace crypto {

#define SHA512_HASH_SIZE      64 // (in bytes)

    using SHA512hash = CryptoHash<SHA512_HASH_SIZE>;

    class SHA512hashing final : public SHA512384hashing<SHA512_HASH_SIZE>
    {
        public:

            SHA512hashing(void);
            virtual ~SHA512hashing() = default;

            SHA512hashing(const SHA512hashing& other) = delete;
            SHA512hashing& operator=(const SHA512hashing& other) = delete;

            SHA512hashing(SHA512hashing&& other) = default;
            SHA512hashing& operator=(SHA512hashing&& other) = default;

        private:

            class SHA512BlockCipherLike final : public SHA512384BlockCipherLike
            {
                public:
                    SHA512BlockCipherLike(void);
                    virtual ~SHA512BlockCipherLike() = default;

                    SHA512BlockCipherLike(const SHA512BlockCipherLike& other) = delete;
                    SHA512BlockCipherLike& operator=(const SHA512BlockCipherLike& other) = delete;

                    SHA512BlockCipherLike(SHA512BlockCipherLike&& other) = default;
                    SHA512BlockCipherLike& operator=(SHA512BlockCipherLike&& other) = default;

                    virtual void reset(void) final override;
            };
    };

} /* namespace crypto */

#endif

