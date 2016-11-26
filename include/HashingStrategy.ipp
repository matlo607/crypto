#include <algorithm>
#include <type_traits>
#include <cassert>

namespace crypto {

    template <typename T, std::size_t N>
        std::ostream& operator<< (std::ostream& stream, const std::array<T,N>& array)
        {
            char oldfill = stream.fill();
            stream.fill('0');

            std::ios_base::fmtflags oldff = stream.flags(), ff = oldff;

            ff &= ~std::ios::basefield;   // unset basefield bits
            ff |= std::ios::hex;          // set hex
            ff &= ~std::ios::adjustfield;
            ff |= std::ios::right;
            ff &= ~std::ios::showbase;    // unset showbase

            stream.flags(ff);

            for (auto elt : array) {
                if (std::is_same<T, uint8_t>::value) {
                    stream.width(sizeof(T) * 2); // width is not sticky as the other flags
                    stream << static_cast<uint16_t>(elt);
                } else {
                    stream << elt;
                }
            }

            stream.fill(oldfill);
            stream.flags(oldff);

            return stream;
        }

    template <size_t N_tmpdigest, typename T_workWord, size_t N_msgBlock, size_t N_digest>
        HashingStrategy<N_tmpdigest,T_workWord,N_msgBlock,N_digest>::HashingStrategy(std::unique_ptr<StrategyBlockCipherLike>&& p) :
            m_msgLength(0),
            m_blockCipherStrategy(std::move(p))
    {}

    template <size_t N_tmpdigest, typename T_workWord, size_t N_msgBlock, size_t N_digest>
        HashingStrategy<N_tmpdigest,T_workWord,N_msgBlock,N_digest>::HashingStrategy(HashingStrategy&& other) :
            m_msgLength(other.m_msgLength),
            m_blockCipherStrategy(std::move(other.m_blockCipherStrategy))
    {}

    template <size_t N_tmpdigest, typename T_workWord, size_t N_msgBlock, size_t N_digest>
        HashingStrategy<N_tmpdigest,T_workWord,N_msgBlock,N_digest>& HashingStrategy<N_tmpdigest,T_workWord,N_msgBlock,N_digest>::operator=(HashingStrategy&& other)
        {
            if (this != &other) {
                m_msgLength = other.m_msgLength;
                m_blockCipherStrategy = std::move(other.m_blockCipherStrategy);
            }
            return *this;
        }

    template <size_t N_tmpdigest, typename T_workWord, size_t N_msgBlock, size_t N_digest>
        bool HashingStrategy<N_tmpdigest,T_workWord,N_msgBlock,N_digest>::update(const uint8_t buf[], size_t len, size_t offset)
        {
            assert(buf != NULL && offset <= len);

            len -= offset;
            buf += offset;

            if (m_msgLength + len > MAX_MSG_LENGTH) {
                return false;
            }

            while (len > 0) {
                size_t written = m_blockCipherStrategy->write(buf, len);
                len -= written;
                m_msgLength += written;
                buf += written;
            }

            return true;
        }

    template <size_t N_tmpdigest, typename T_workWord, size_t N_msgBlock, size_t N_digest>
        CryptoHash<N_digest> HashingStrategy<N_tmpdigest,T_workWord,N_msgBlock,N_digest>::getHash(void)
        {
            // size of the message in bits
            CryptoHash<N_digest> digest = m_blockCipherStrategy->addPadding(m_msgLength * 8);

            // message may be sensitive, clear it out
            m_blockCipherStrategy->reset();

            // reset hash context
            m_msgLength = 0;

            return std::move(digest);
        }

    template <size_t N_tmpdigest, typename T_workWord, size_t N_msgBlock, size_t N_digest>
        HashingStrategy<N_tmpdigest,T_workWord,N_msgBlock,N_digest>::StrategyBlockCipherLike::StrategyBlockCipherLike() :
            m_msgBlockIndex(0) {}

    template <size_t N_tmpdigest, typename T_workWord, size_t N_msgBlock, size_t N_digest>
        HashingStrategy<N_tmpdigest,T_workWord,N_msgBlock,N_digest>::StrategyBlockCipherLike::StrategyBlockCipherLike(StrategyBlockCipherLike&& other) :
            m_msgBlock(std::move(other.m_msgBlock)),
            m_msgBlockIndex(other.m_msgBlockIndex),
            m_intermediateHash(std::move(other.m_intermediateHash))
    {}

    template <size_t N_tmpdigest, typename T_workWord, size_t N_msgBlock, size_t N_digest>
        typename HashingStrategy<N_tmpdigest,T_workWord,N_msgBlock,N_digest>::StrategyBlockCipherLike&
        HashingStrategy<N_tmpdigest,T_workWord,N_msgBlock,N_digest>::StrategyBlockCipherLike::operator=(StrategyBlockCipherLike&& other)
        {
            if (this != &other) {
                m_msgBlockIndex = other.m_msgBlockIndex;
                m_msgBlock = std::move(other.m_msgBlock);
                m_intermediateHash = std::move(other.m_intermediateHash);
            }
            return *this;
        }


    template <size_t N_tmpdigest, typename T_workWord, size_t N_msgBlock, size_t N_digest>
        size_t HashingStrategy<N_tmpdigest,T_workWord,N_msgBlock,N_digest>::StrategyBlockCipherLike::write(const uint8_t buf[], size_t len)
        {
            assert(buf != NULL && len > 0);

            auto writable = sizeof(MsgBlock_uint8<N_msgBlock>) - m_msgBlockIndex;
            bool processing = (len >= writable);
            auto toWrite = processing ? writable : len;

            memcpy(m_msgBlock.data() + m_msgBlockIndex, buf, toWrite);

            if (processing) {
                process();
            } else {
                m_msgBlockIndex += len;
            }

            return toWrite;
        }

    template <size_t N_tmpdigest, typename T_workWord, size_t N_msgBlock, size_t N_digest>
        CryptoHash<N_digest> HashingStrategy<N_tmpdigest,T_workWord,N_msgBlock,N_digest>::StrategyBlockCipherLike::addPadding(size_t len)
        {
            auto const MSGLENGTH_offset =
                (std::is_same<T_workWord, uint64_t>::value) ?
                sizeof(MsgBlock_uint8<N_msgBlock>) - sizeof(uint64_t) * 2 :
                sizeof(MsgBlock_uint8<N_msgBlock>) - sizeof(uint64_t);

            // Write a "1" followed by 7 "0"s
            m_msgBlock[m_msgBlockIndex++] = 0x80;

            auto it = m_msgBlock.begin() + m_msgBlockIndex;

            // Do we have the space to write the length of the message ?
            if(m_msgBlockIndex > MSGLENGTH_offset)
            {
                // Pad with "0"s until the end of the block and create a new block
                std::fill_n(it, m_msgBlock.end() - it, 0x00);
                process();
                it = m_msgBlock.begin();
            }

            // Pad with "0"s until the message length's offset
            std::fill_n(it, m_msgBlock.begin() + MSGLENGTH_offset - it, 0x00);

            // Store the message length as the last 8 octets
            setMsgSize(len);

            process();

            return std::move(getDigest());
        }

} /* namespace crypto */

