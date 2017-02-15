#ifndef _MD5_HASHING_
#define _MD5_HASHING_

#include "HashingStrategy.hpp"

namespace crypto {

#define MD5_HASH_SIZE      16 // (in bytes)

    using MD5hash = CryptoHash<MD5_HASH_SIZE>;

    class MD5hashing : public HashingStrategy<MD5_HASH_SIZE>
    {
        public:

            MD5hashing(void);
            ~MD5hashing() = default;

            MD5hashing(const MD5hashing& other) = delete;
            MD5hashing& operator=(const MD5hashing& other) = delete;

            MD5hashing(MD5hashing&& other) = default;
            MD5hashing& operator=(MD5hashing&& other) = default;

        private:

            using HS = HashingStrategy<MD5_HASH_SIZE>;
            using HSBC = HS::StrategyBlockCipherLike;

            class MD5BlockCipherLike final : public StrategyBlockCipherLike
            {
                private:
                    virtual void process(void) final override;
                    virtual MD5hash getDigest(void) final override;
                    virtual void setMsgSize(size_t size) final override;

                public:
                    MD5BlockCipherLike(void);
                    ~MD5BlockCipherLike() = default;

                    MD5BlockCipherLike(const MD5BlockCipherLike& other) = delete;
                    MD5BlockCipherLike& operator=(const MD5BlockCipherLike& other) = delete;

                    MD5BlockCipherLike(MD5BlockCipherLike&& other) = default;
                    MD5BlockCipherLike& operator=(MD5BlockCipherLike&& other) = default;

                    void reset(void) final override;
            };
    };

} /* namespace crypto */

#endif
