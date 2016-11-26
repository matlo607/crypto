#ifndef _SHA1_HASHING_
#define _SHA1_HASHING_

#include "HashingStrategy.hpp"

namespace crypto {

#define SHA1_HASH_SIZE      20 // (in bytes)
#define SHA1_MSGBLOCK_SIZE  64 // (in bytes)

    using SHA1hash = CryptoHash<SHA1_HASH_SIZE>;

    class SHA1hashing final : public HashingStrategy<SHA1_HASH_SIZE, uint32_t, SHA1_MSGBLOCK_SIZE>
    {
        public:

            SHA1hashing(void);
            ~SHA1hashing() = default;

            SHA1hashing(const SHA1hashing& other) = delete;
            SHA1hashing& operator=(const SHA1hashing& other) = delete;

            SHA1hashing(SHA1hashing&& other) = default;
            SHA1hashing& operator=(SHA1hashing&& other) = default;

        private:

            class SHA1BlockCipherLike final : public StrategyBlockCipherLike
            {
                private:
                    virtual void process(void) final override;
                    virtual SHA1hash getDigest(void) final override;
                    virtual void setMsgSize(size_t size) final override;

                public:
                    SHA1BlockCipherLike(void);
                    ~SHA1BlockCipherLike() = default;

                    SHA1BlockCipherLike(const SHA1BlockCipherLike& other) = delete;
                    SHA1BlockCipherLike& operator=(const SHA1BlockCipherLike& other) = delete;

                    SHA1BlockCipherLike(SHA1BlockCipherLike&& other) = default;
                    SHA1BlockCipherLike& operator=(SHA1BlockCipherLike&& other) = default;

                    void reset(void) final override;
            };
    };

} /* namespace crypto */

#endif

