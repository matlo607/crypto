#include <algorithm>
#include <type_traits>
#include <cassert>

namespace crypto {

    template <typename T, std::ptrdiff_t N>
        std::ostream& operator<< (std::ostream& stream, const gsl::span<T,N>& span)
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

            for (auto elt : span) {
                if (std::is_same<typename std::remove_cv<T>::type, uint8_t>::value) {
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

    template <size_t N_tmpdigest, size_t N_digest, typename T_subTypeBlock, size_t N_blockSize>
        HashingStrategy<N_tmpdigest,N_digest,T_subTypeBlock,N_blockSize>::HashingStrategy(std::unique_ptr<StrategyBlockCipherLike>&& p) :
            m_msgLength(0),
            m_blockCipherStrategy(std::move(p))
    {}

    template <size_t N_tmpdigest, size_t N_digest, typename T_subTypeBlock, size_t N_blockSize>
        HashingStrategy<N_tmpdigest,N_digest,T_subTypeBlock,N_blockSize>::HashingStrategy(HashingStrategy&& other) :
            m_msgLength(other.m_msgLength),
            m_blockCipherStrategy(std::move(other.m_blockCipherStrategy))
    {}

    template <size_t N_tmpdigest, size_t N_digest, typename T_subTypeBlock, size_t N_blockSize>
        HashingStrategy<N_tmpdigest,N_digest,T_subTypeBlock,N_blockSize>& HashingStrategy<N_tmpdigest,N_digest,T_subTypeBlock,N_blockSize>::operator=(HashingStrategy&& other)
        {
            if (this != &other) {
                m_msgLength = other.m_msgLength;
                m_blockCipherStrategy = std::move(other.m_blockCipherStrategy);
            }
            return *this;
        }

    template <size_t N_tmpdigest, size_t N_digest, typename T_subTypeBlock, size_t N_blockSize>
        bool HashingStrategy<N_tmpdigest,N_digest,T_subTypeBlock,N_blockSize>::update(gsl::span<const uint8_t> &buf)
        {
            assert(buf.data() != nullptr && !buf.empty());

            if (m_msgLength + buf.size() > MAX_MSG_LENGTH) {
                return false;
            }

            auto in(buf);
            while ( !in.empty() ) {
                auto written = m_blockCipherStrategy->write(in);
                in = in.subspan(written);

                // update message length
                m_msgLength += written;
            }

            return true;
        }

    template <size_t N_tmpdigest, size_t N_digest, typename T_subTypeBlock, size_t N_blockSize>
        CryptoHash<N_digest> HashingStrategy<N_tmpdigest,N_digest,T_subTypeBlock,N_blockSize>::getHash(void)
        {
            // size of the message in bits
            CryptoHash<N_digest> digest = m_blockCipherStrategy->addPadding(m_msgLength * 8);

            // message may be sensitive, clear it out
            m_blockCipherStrategy->reset();

            // reset hash context
            m_msgLength = 0;

            return std::move(digest);
        }

    template <size_t N_tmpdigest, size_t N_digest, typename T_subTypeBlock, size_t N_blockSize>
        HashingStrategy<N_tmpdigest,N_digest,T_subTypeBlock,N_blockSize>::StrategyBlockCipherLike::StrategyBlockCipherLike() :
            m_spaceAvailable(m_msgBlock)
    {}

    template <size_t N_tmpdigest, size_t N_digest, typename T_subTypeBlock, size_t N_blockSize>
        HashingStrategy<N_tmpdigest,N_digest,T_subTypeBlock,N_blockSize>::StrategyBlockCipherLike::StrategyBlockCipherLike(StrategyBlockCipherLike&& other) :
            m_msgBlock(std::move(other.m_msgBlock)),
            m_spaceAvailable(gsl::span<uint8_t>(m_msgBlock).subspan(
                        m_msgBlock.size() - other.m_spaceAvailable.size())),
            m_intermediateHash(std::move(other.m_intermediateHash))
    {}

    template <size_t N_tmpdigest, size_t N_digest, typename T_subTypeBlock, size_t N_blockSize>
        typename HashingStrategy<N_tmpdigest,N_digest,T_subTypeBlock,N_blockSize>::StrategyBlockCipherLike&
        HashingStrategy<N_tmpdigest,N_digest,T_subTypeBlock,N_blockSize>::StrategyBlockCipherLike::operator=(StrategyBlockCipherLike&& other)
        {
            if (this != &other) {
                m_msgBlock = std::move(other.m_msgBlock);
                m_intermediateHash = std::move(other.m_intermediateHash);
                m_spaceAvailable = gsl::span<uint8_t>(m_msgBlock).subspan(
                        m_msgBlock.size() - other.m_spaceAvailable.size());
            }
            return *this;
        }


    template <size_t N_tmpdigest, size_t N_digest, typename T_subTypeBlock, size_t N_blockSize>
        size_t HashingStrategy<N_tmpdigest,N_digest,T_subTypeBlock,N_blockSize>::StrategyBlockCipherLike::write(gsl::span<const uint8_t> &buf)
        {
            assert(buf.data() != nullptr && !buf.empty());

            auto n = std::min(m_spaceAvailable.size(), buf.size());
            std::copy_n(buf.begin(), n, m_spaceAvailable.begin());

            if (n == m_spaceAvailable.size()) {
                process();
                m_spaceAvailable = gsl::span<uint8_t>(m_msgBlock);
            } else {
                m_spaceAvailable = m_spaceAvailable.subspan(n);
            }

            return n;
        }

    template <size_t N_tmpdigest, size_t N_digest, typename T_subTypeBlock, size_t N_blockSize>
        CryptoHash<N_digest> HashingStrategy<N_tmpdigest,N_digest,T_subTypeBlock,N_blockSize>::StrategyBlockCipherLike::addPadding(size_t len)
        {
            // Usually the size is encoded on 64bits although in new hashing algorithms like SHA512 this size's encoding was increased to 128bits.
            // Given the probability of meeting a file with a size greater than 2^64-1 nowadays, and the possibilities of handling such numbers with
            // the C++ native features, we will stick for simplicity to file's effective size encoded on 64 bits.
            constexpr auto const MSG_BLOCK_SIZE = std::tuple_size<decltype(m_msgBlock)>::value;
            constexpr auto const offset_MSGLENGTH =
                (std::is_same<T_subTypeBlock, uint64_t>::value) ?
                MSG_BLOCK_SIZE - sizeof(uint64_t) * 2 :
                MSG_BLOCK_SIZE - sizeof(uint64_t);

            gsl::span<uint8_t> msgBlock { m_msgBlock };

            auto const it_MSGLENGTH = std::next(msgBlock.begin(), offset_MSGLENGTH);
            auto it = std::next(msgBlock.begin(), msgBlock.size() - m_spaceAvailable.size());

            // Write a "1" followed by 7 "0"s
            *it++ = 0x80;

            // Do we have the space to write the length of the message ?
            if (std::distance(it, it_MSGLENGTH) < 0) {
                // Pad with "0"s until the end of the block and create a new block
                std::fill(it, msgBlock.end(), 0);
                process();

                it = msgBlock.begin();
            }

            // Pad with "0"s until the message length's offset
            std::fill(it, it_MSGLENGTH, 0);

            // Store the message length as the last 8 octets
            setMsgSize(len);

            process();

            return std::move(getDigest());
        }

} /* namespace crypto */

