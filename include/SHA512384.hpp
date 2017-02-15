#ifndef _SHA512384_HASHING_
#define _SHA512384_HASHING_

#include "HashingStrategy.hpp"

namespace crypto {

#define SHA512384_TMPHASH_SIZE   64 // (in bytes)

    template <size_t N>
        using SHA512384hash = CryptoHash<N>;

    template <size_t N_digest>
        class SHA512384hashing : public HashingStrategy<SHA512384_TMPHASH_SIZE, N_digest, uint64_t>
    {
        protected:

            SHA512384hashing(void) = delete;
            virtual ~SHA512384hashing() = default;

            SHA512384hashing(const SHA512384hashing& other) = delete;
            SHA512384hashing& operator=(const SHA512384hashing& other) = delete;

            SHA512384hashing(SHA512384hashing&& other) = default;
            SHA512384hashing& operator=(SHA512384hashing&& other) = default;

            template <size_t N>
                using HS = HashingStrategy<SHA512384_TMPHASH_SIZE, N, uint64_t>;

            template <size_t N>
                using HSBC = typename HS<N>::StrategyBlockCipherLike;

            class SHA512384BlockCipherLike : public HS<N_digest>::StrategyBlockCipherLike
            {
                private:
                    virtual void process(void) final override;
                    virtual SHA512384hash<N_digest> getDigest(void) final override;
                    virtual void setMsgSize(size_t size) final override;

                public:
                    SHA512384BlockCipherLike(void) = default;
                    virtual ~SHA512384BlockCipherLike() = default;

                    SHA512384BlockCipherLike(const SHA512384BlockCipherLike& other) = delete;
                    SHA512384BlockCipherLike& operator=(const SHA512384BlockCipherLike& other) = delete;

                    SHA512384BlockCipherLike(SHA512384BlockCipherLike&& other) = default;
                    SHA512384BlockCipherLike& operator=(SHA512384BlockCipherLike&& other) = default;

                    virtual void reset(void) = 0;
            };

            SHA512384hashing(std::unique_ptr< typename HS<N_digest>::StrategyBlockCipherLike >&& p);
    };

} /* namespace crypto */

#include "SHA512384.ipp"

#endif

