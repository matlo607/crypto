#ifndef _SHA256_HASHING_
#define _SHA256_HASHING_

#include "HashingStrategy.hpp"

namespace crypto {

#define SHA256_HASH_SIZE      32 // (in bytes)
#define SHA256_MSGBLOCK_SIZE  64 // (in bytes)

    using SHA256hash = CryptoHash<SHA256_HASH_SIZE>;

    class SHA256hashing final : public HashingStrategy<SHA256_HASH_SIZE, SHA256_MSGBLOCK_SIZE>
    {
        public:

            SHA256hashing(void);
            ~SHA256hashing() = default;

            SHA256hashing(const SHA256hashing& other) = delete;
            SHA256hashing& operator=(const SHA256hashing& other) = delete;

            SHA256hashing(SHA256hashing&& other) = default;
            SHA256hashing& operator=(SHA256hashing&& other) = default;

        private:

            class SHA256BlockCipherLike final : public StrategyBlockCipherLike
            {
                private:
                    virtual void process(void) final override;
                    virtual SHA256hash getDigest(void) final override;
                    virtual void setMsgSize(size_t size) final override;

                public:
                    SHA256BlockCipherLike(void);
                    ~SHA256BlockCipherLike() = default;

                    SHA256BlockCipherLike(const SHA256BlockCipherLike& other) = delete;
                    SHA256BlockCipherLike& operator=(const SHA256BlockCipherLike& other) = delete;

                    SHA256BlockCipherLike(SHA256BlockCipherLike&& other) = default;
                    SHA256BlockCipherLike& operator=(SHA256BlockCipherLike&& other) = default;

                    void reset(void) final override;
            };
    };

} /* namespace crypto */

#endif

