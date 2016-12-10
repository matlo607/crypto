#ifndef _SHA384_HASHING_
#define _SHA384_HASHING_

#include "SHA512384.hpp"

namespace crypto {

#define SHA384_HASH_SIZE      48 // (in bytes)

    using SHA384hash = CryptoHash<SHA384_HASH_SIZE>;

    class SHA384hashing final : public SHA512384hashing<SHA384_HASH_SIZE>
    {
        public:

            SHA384hashing(void);
            virtual ~SHA384hashing() = default;

            SHA384hashing(const SHA384hashing& other) = delete;
            SHA384hashing& operator=(const SHA384hashing& other) = delete;

            SHA384hashing(SHA384hashing&& other) = default;
            SHA384hashing& operator=(SHA384hashing&& other) = default;

        private:

            class SHA384BlockCipherLike final : public SHA512384BlockCipherLike
        {
            public:
                SHA384BlockCipherLike(void);
                virtual ~SHA384BlockCipherLike() = default;

                SHA384BlockCipherLike(const SHA384BlockCipherLike& other) = delete;
                SHA384BlockCipherLike& operator=(const SHA384BlockCipherLike& other) = delete;

                SHA384BlockCipherLike(SHA384BlockCipherLike&& other) = default;
                SHA384BlockCipherLike& operator=(SHA384BlockCipherLike&& other) = default;

                virtual void reset(void) final override;
        };
    };

} /* namespace crypto */

#endif

