#ifndef _HASHING_STRATEGY_HPP
#define _HASHING_STRATEGY_HPP

#include <cstdint>
#include <array>
#include <iostream>
#include <memory>

namespace crypto {

    template <typename T, size_t N>
        std::ostream& operator<< (std::ostream& stream, const std::array<T,N>& array);

    template <size_t N>
        using CryptoHash_uint8 = std::array<uint8_t, N>;

    template <size_t N>
        using CryptoHash_uint32 = std::array<uint32_t, N / sizeof(uint32_t)>;

    template <size_t N>
        using CryptoHash_uint64 = std::array<uint64_t, N / sizeof(uint64_t)>;

    template <size_t N>
        using MsgBlock_uint8 = std::array<uint8_t, N>;

    template <size_t N>
        using MsgBlock_uint32 = std::array<uint32_t, N / sizeof(uint32_t)>;

    template <size_t N>
        using MsgBlock_uint64 = std::array<uint64_t, N / sizeof(uint64_t)>;

    template <size_t N>
        using CryptoHash = CryptoHash_uint8<N>;

    template <size_t N_digest, size_t N_msgBlock>
        class HashingStrategy
        {
            public:

                virtual ~HashingStrategy() = default;

                bool update(const uint8_t array[], size_t size, size_t offset = 0);
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

                        StrategyBlockCipherLike(void);
                        virtual ~StrategyBlockCipherLike() = default;

                        StrategyBlockCipherLike(const StrategyBlockCipherLike& other) = delete;
                        StrategyBlockCipherLike& operator=(const StrategyBlockCipherLike& other) = delete;

                        StrategyBlockCipherLike(StrategyBlockCipherLike&& other);
                        StrategyBlockCipherLike& operator=(StrategyBlockCipherLike&& other);

                        size_t write(const uint8_t buf[], size_t len);
                        CryptoHash<N_digest> addPadding(size_t totalMsgLength);
                        virtual void reset(void) = 0;

                    protected:

                        MsgBlock_uint8<N_msgBlock> m_msgBlock;
                        uint16_t m_msgBlockIndex;

                        CryptoHash_uint32<N_digest> m_intermediateHash;

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

