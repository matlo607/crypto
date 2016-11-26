#ifndef _MD4_HASHING_
#define _MD4_HASHING_

#include "HashingStrategy.hpp"

namespace crypto {

#define MD4_HASH_SIZE      16 // (in bytes)
#define MD4_MSGBLOCK_SIZE  64 // (in bytes)

    using MD4hash = CryptoHash<MD4_HASH_SIZE>;

    class MD4hashing : public HashingStrategy<MD4_HASH_SIZE, uint32_t, MD4_MSGBLOCK_SIZE>
    {
        public:

            MD4hashing(void);
            ~MD4hashing() = default;

            MD4hashing(const MD4hashing& other) = delete;
            MD4hashing& operator=(const MD4hashing& other) = delete;

            MD4hashing(MD4hashing&& other) = default;
            MD4hashing& operator=(MD4hashing&& other) = default;

        private:

            class MD4BlockCipherLike final : public StrategyBlockCipherLike
            {
                private:
                    virtual void process(void) final override;
                    virtual MD4hash getDigest(void) final override;
                    virtual void setMsgSize(size_t size) final override;

                public:
                    MD4BlockCipherLike(void);
                    ~MD4BlockCipherLike() = default;

                    MD4BlockCipherLike(const MD4BlockCipherLike& other) = delete;
                    MD4BlockCipherLike& operator=(const MD4BlockCipherLike& other) = delete;

                    MD4BlockCipherLike(MD4BlockCipherLike&& other) = default;
                    MD4BlockCipherLike& operator=(MD4BlockCipherLike&& other) = default;

                    void reset(void) final override;
            };
    };

} /* namespace crypto */

#endif
