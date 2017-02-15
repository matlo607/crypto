#ifndef _HASHING_STRATEGY_HPP
#define _HASHING_STRATEGY_HPP

#include <cstdint>
#include <array>
#include <iostream>
#include <memory>
#include <gsl/span>

namespace crypto {

    template <typename T, std::ptrdiff_t N>
        std::ostream& operator<< (std::ostream& stream, const gsl::span<T,N>& array);

    template <size_t N>
        using CryptoHash_uint8 = std::array<uint8_t, N>;

    template <size_t N>
        using CryptoHash_uint32 = std::array<uint32_t, N / sizeof(uint32_t)>;

    template <size_t N>
        using CryptoHash_uint64 = std::array<uint64_t, N / sizeof(uint64_t)>;

    template <size_t N>
        using CryptoHash = CryptoHash_uint8<N>;

    template <size_t N_tmpdigest, size_t N_digest = N_tmpdigest,
              typename T_subTypeBlock = uint32_t,
              size_t N_blockSize = 16 * sizeof(T_subTypeBlock)>
        class HashingStrategy
        {
            public:

                virtual ~HashingStrategy() = default;

                bool update(gsl::span<const uint8_t> &buf);
                CryptoHash<N_digest> getHash(void);

            protected:

                class StrategyBlockCipherLike;

                HashingStrategy(std::unique_ptr<StrategyBlockCipherLike>&& p);
                HashingStrategy(void) = delete;
                HashingStrategy(const HashingStrategy& other) = delete;
                HashingStrategy& operator=(const HashingStrategy& other) = delete;

                HashingStrategy(HashingStrategy&& other);
                HashingStrategy& operator=(HashingStrategy&& other);

                class StrategyBlockCipherLike
                {
                    public:

                        using MsgBlock_uint8 = std::array<uint8_t, N_blockSize>;
                        using MsgBlock_uint32 = std::array<uint32_t, sizeof(MsgBlock_uint8) / sizeof(uint32_t)>;
                        using MsgBlock_uint64 = std::array<uint64_t, sizeof(MsgBlock_uint8) / sizeof(uint64_t)>;

                        StrategyBlockCipherLike(void);
                        virtual ~StrategyBlockCipherLike() = default;

                        StrategyBlockCipherLike(const StrategyBlockCipherLike& other) = delete;
                        StrategyBlockCipherLike& operator=(const StrategyBlockCipherLike& other) = delete;

                        StrategyBlockCipherLike(StrategyBlockCipherLike&& other);
                        StrategyBlockCipherLike& operator=(StrategyBlockCipherLike&& other);

                        size_t write(gsl::span<const uint8_t> &buf);
                        CryptoHash<N_digest> addPadding(size_t totalMsgLength);
                        virtual void reset(void) = 0;

                    protected:

                        MsgBlock_uint8 m_msgBlock;
                        gsl::span<uint8_t> m_spaceAvailable;

                        std::array<T_subTypeBlock, N_tmpdigest / sizeof(T_subTypeBlock)> m_intermediateHash;

                        virtual void process(void) = 0;
                        virtual CryptoHash<N_digest> getDigest(void) = 0;
                        virtual void setMsgSize(size_t size) = 0;
                };

                // maximum length of a hashed message (in bytes)
                static const uint64_t MAX_MSG_LENGTH = 1UL << 61; // 2^64 bits <=> 2^61 bytes;

                uint64_t m_msgLength; // length of the message (in bytes)

                std::unique_ptr<StrategyBlockCipherLike> m_blockCipherStrategy;
        };

} /* namespace crypto */

#include "HashingStrategy.ipp"

#endif /* _HASHING_STRATEGY_HPP */
