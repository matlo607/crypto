#ifndef _SHA256224_HASHING_
#define _SHA256224_HASHING_

#include "HashingStrategy.hpp"

namespace crypto {

#define SHA256224_TMPHASH_SIZE   32 // (in bytes)
#define SHA256224_MSGBLOCK_SIZE  64 // (in bytes)

    template <size_t N>
        using SHA256224hash = CryptoHash<N>;

    template <size_t N_digest>
        class SHA256224hashing : public HashingStrategy<SHA256224_TMPHASH_SIZE, uint32_t, SHA256224_MSGBLOCK_SIZE, N_digest>
    {
        protected:

            class SHA256224BlockCipherLike;

            template <size_t N>
                using HS = HashingStrategy<SHA256224_TMPHASH_SIZE, uint32_t, SHA256224_MSGBLOCK_SIZE, N>;

            SHA256224hashing(std::unique_ptr< typename HS<N_digest>::StrategyBlockCipherLike >&& p);
            SHA256224hashing(void) = delete;
            virtual ~SHA256224hashing() = default;

            SHA256224hashing(const SHA256224hashing& other) = delete;
            SHA256224hashing& operator=(const SHA256224hashing& other) = delete;

            SHA256224hashing(SHA256224hashing&& other) = default;
            SHA256224hashing& operator=(SHA256224hashing&& other) = default;

            class SHA256224BlockCipherLike : public HS<N_digest>::StrategyBlockCipherLike
            {
                private:
                    virtual void process(void) final override;
                    virtual SHA256224hash<N_digest> getDigest(void) final override;
                    virtual void setMsgSize(size_t size) final override;

                public:
                    SHA256224BlockCipherLike(void) = default;
                    virtual ~SHA256224BlockCipherLike() = default;

                    SHA256224BlockCipherLike(const SHA256224BlockCipherLike& other) = delete;
                    SHA256224BlockCipherLike& operator=(const SHA256224BlockCipherLike& other) = delete;

                    SHA256224BlockCipherLike(SHA256224BlockCipherLike&& other) = default;
                    SHA256224BlockCipherLike& operator=(SHA256224BlockCipherLike&& other) = default;

                    virtual void reset(void) = 0;
            };

    };

} /* namespace crypto */

#include "SHA256224.ipp"

#endif

