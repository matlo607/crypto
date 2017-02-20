#ifndef _DUMMY_HASHING_
#define _DUMMY_HASHING_

#include "HashingStrategy.hpp"
#include "endian.hpp"

namespace crypto {

#define DUMMY_HASH_SIZE      16 // (in bytes)

    using DUMMYhash = CryptoHash<DUMMY_HASH_SIZE>;

    class DUMMYhashing : public HashingStrategy<DUMMY_HASH_SIZE>
    {
        public:

            DUMMYhashing(void) : HS(std::make_unique<DUMMYhashing::DUMMYBlockCipherLike>()) {}
            ~DUMMYhashing() = default;

            DUMMYhashing(const DUMMYhashing& other) = delete;
            DUMMYhashing& operator=(const DUMMYhashing& other) = delete;

            DUMMYhashing(DUMMYhashing&& other) = default;
            DUMMYhashing& operator=(DUMMYhashing&& other) = default;

        private:

            using HS = HashingStrategy<DUMMY_HASH_SIZE>;
            using HSBC = HS::StrategyBlockCipherLike;

            class DUMMYBlockCipherLike final : public StrategyBlockCipherLike
            {
                private:
                    virtual void process(void) final override
                    {
                        auto& msgBlock = *reinterpret_cast<MsgBlock_uint32*>(m_msgBlock.data());

                        // initialize the first 16 words in the array W
                        std::for_each(msgBlock.begin(),
                                      msgBlock.end(),
                                      [](uint32_t n) { return htole32(n); });

                        uint32_t A = m_intermediateHash[0];
                        uint32_t B = m_intermediateHash[1];
                        uint32_t C = m_intermediateHash[2];
                        uint32_t D = m_intermediateHash[3];

                        for (uint16_t i=0; i < msgBlock.size(); i+=4) {
                            A += msgBlock[i];
                            B += msgBlock[i+1];
                            C += msgBlock[i+2];
                            D += msgBlock[i+3];
                        }

                        m_intermediateHash[0] += A;
                        m_intermediateHash[1] += B;
                        m_intermediateHash[2] += C;
                        m_intermediateHash[3] += D;
                    }

                    virtual DUMMYhash getDigest(void) final override
                    {
                        DUMMYhash digest;

#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
                        auto& dest = *reinterpret_cast<DUMMYhash_uint32*>(digest.data());

                        // write the hash in little endian
                        std::transform(m_intermediateHash.begin(),
                                       std::next(dest.begin(), N_digest / sizeof(uint32_t)),
                                       dest.begin(),
                                       [] (uint32_t n) { return htole32(n); });
#else
                        auto& temporary = *reinterpret_cast<DUMMYhash*>(m_intermediateHash.data());

                        std::copy(temporary.begin(), temporary.end(), digest.begin());
#endif

                        return std::move(digest);
                    }

                    virtual void setMsgSize(size_t size) final override
                    {
                        auto& dest = *reinterpret_cast<HSBC::MsgBlock_uint64*>(m_msgBlock.data());
                        dest.back() = htole64(size);
                    }

                public:
                    DUMMYBlockCipherLike(void) : HS::StrategyBlockCipherLike() { reset(); }
                    ~DUMMYBlockCipherLike() = default;

                    DUMMYBlockCipherLike(const DUMMYBlockCipherLike& other) = delete;
                    DUMMYBlockCipherLike& operator=(const DUMMYBlockCipherLike& other) = delete;

                    DUMMYBlockCipherLike(DUMMYBlockCipherLike&& other) = default;
                    DUMMYBlockCipherLike& operator=(DUMMYBlockCipherLike&& other) = default;

                    void reset(void) final override
                    {
                        m_msgBlock.fill(0);
                        m_spaceAvailable = m_msgBlock;
                        m_intermediateHash = { 0x0 };
                    }
            };
    };

} /* namespace crypto */


#endif
