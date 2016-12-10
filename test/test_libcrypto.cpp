#include "gtest/gtest.h"

#include "utils.hpp"
#include "HashingStrategy.hpp"
#include "SHA1.hpp"
#include "SHA224.hpp"
#include "SHA256.hpp"
#include "SHA384.hpp"
#include "SHA512.hpp"
#include "MD4.hpp"
#include "MD5.hpp"

#include <string>
#include <sstream>
#include <algorithm>
#include <utility>

#include <sys/time.h>

using std::cout;
using std::endl;

//#define SHOW_TIMING

class TestEnvironment : public ::testing::Environment {
    public:
        static const std::string& getTxt1() {
            static const std::string Txt1 = "abc";
            return Txt1;
        }

        static const std::string& getTxt2() {
            static const std::string Txt2 = "Neque porro quisquam est qui dolorem ipsum quia dolor sit amet, consectetur, adipisci velit...";
            return Txt2;
        }

        static const std::string& getTxt3() {
            static const std::string Txt3 = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Mauris magna eros, accumsan vitae malesuada eu, suscipit tincidunt lectus. Vivamus quam odio, dapibus vitae dignissim sed, eleifend et libero. Suspendisse potenti. Ut elementum orci consequat feugiat tincidunt. Sed molestie hendrerit risus a scelerisque. Nullam ut semper magna. Maecenas nisl libero, fermentum quis nisi posuere, semper euismod metus. Duis accumsan lectus non justo pulvinar condimentum. Integer interdum nisi diam, a luctus urna molestie quis. Vestibulum auctor volutpat luctus. Sed sodales vitae erat at scelerisque. Cras eu metus ut elit efficitur sodales sed ac mauris. Cras et maximus arcu. Donec quis sagittis nunc. Integer pretium, arcu nec efficitur mollis, neque dolor pretium mauris, nec accumsan felis libero vel lacus. Maecenas laoreet a est et dapibus. Sed eget leo interdum, vestibulum justo ultrices, fringilla neque. Nulla et mi libero. Aenean bibendum pretium quam vel lacinia. Donec tincidunt leo eget ornare efficitur. Nulla at convallis libero. Morbi nulla tellus, commodo at mi ac, ultricies interdum sapien. Vestibulum imperdiet vel mauris in euismod. Nam blandit finibus consequat. Phasellus quis ornare velit. Nunc ex mi, condimentum id scelerisque quis, pellentesque id lectus. Donec ac risus finibus, mollis dolor sed, sagittis ex. Pellentesque nisl sapien, pellentesque quis condimentum vitae, volutpat at eros. Vivamus suscipit libero quis mi mollis dictum. Praesent id nisl elementum, luctus purus eu, dictum sem. Sed ac condimentum diam, vitae semper lectus. Vestibulum ante ipsum primis in faucibus orci luctus et ultrices posuere cubilia Curae; Quisque non tellus lobortis, ornare urna at, iaculis lacus. Ut rhoncus, justo auctor vulputate ultricies, tortor dolor commodo est, at tincidunt tortor mauris in libero. Proin convallis mauris eget lacus placerat venenatis. Sed maximus enim at nunc rutrum, at elementum quam congue. Ut euismod lacus massa, ut consectetur augue vulputate vitae. Suspendisse tempor pretium urna, sit amet cursus ligula faucibus in. Quisque gravida quam sodales justo finibus, et eleifend purus convallis. Aenean a pellentesque felis, ac vehicula libero. Suspendisse dictum non quam a congue. Etiam scelerisque, nunc vitae dictum vestibulum, metus ligula bibendum ligula, eget tempus lectus massa id velit. Duis eu aliquet risus. Aenean aliquet, velit in facilisis fringilla, orci leo gravida augue, non consectetur enim leo eget leo. Phasellus lorem augue, sollicitudin sed tempus quis, finibus eget justo. Cras arcu nisi, viverra vitae ullamcorper tincidunt, interdum vel urna. Suspendisse potenti. Nunc tempus magna eu dui consectetur semper. Maecenas iaculis magna eget rhoncus porttitor. Ut tempor pharetra odio et dignissim. Maecenas facilisis, velit eu feugiat maximus, nunc sem suscipit eros, vitae mollis magna arcu quis tortor.";
            return Txt3;
        }

        static const std::string& getTxt4() {
            static const std::string Txt4 = "Neque porro quisquam est qui dolorem ipsum quia dolor sit amet, ";
            return Txt4;
        }

        static const std::string& getTxt5() {
            static const std::string Txt5 = "Neque porro quisquam est qui dolorem ipsum quia dolor sit am";
            return Txt5;
        }

        static const std::string& getTxt6() {
            static const std::string Txt6 = "English has developed over the course of more than 1,400 years. The earliest forms of English, a set of Anglo-Frisian dialects brought to Great Britain by Anglo-Saxon settlers in the fifth century, are called Old English. Middle English began in the late 11th century with the Norman conquest of England, and was a period in which the language was influenced by French.[9] Early Modern English began in the late 15th century with the introduction of the printing press to London and the King James Bible, and the start of the Great Vowel Shift.[10] Through the worldwide influence of the British Empire, modern English spread around the world from the 17th to mid-20th centuries. Through all types of printed and electronic media, as well as the emergence of the United States as a global superpower, English has become the leading language of international discourse and the lingua franca in many regions and in professional contexts such as science, navigation, and law.[11] Modern English has little inflection compared with many other languages, and relies more on auxiliary verbs and word order for the expression of complex tenses, aspect and mood, as well as passive constructions, interrogatives and some negation. Despite noticeable variation among the accents and dialects of English used in different countries and regions – in terms of phonetics and phonology, and sometimes also vocabulary, grammar and spelling – English-speakers from around the world are able to communicate with one another with relative ease.";
            return Txt6;
        }

        virtual void SetUp() { }
};

using crypto::operator<<;

template <size_t N>
using HashChallenges = std::array< std::pair<const std::string, const std::string>, N >;

template <size_t N_tmphashSize, typename T_workWord, size_t N_blockSize, size_t N_hashSize>
using HS = crypto::HashingStrategy< N_tmphashSize, T_workWord, N_blockSize, N_hashSize >;

template <size_t N_challenges, typename T_workWord, size_t N_tmphashSize, size_t N_blockSize, size_t N_hashSize>
void hashProve(HashChallenges<N_challenges>& challenges, HS<N_tmphashSize,T_workWord,N_blockSize, N_hashSize>&& strategy)
{
    std::stringstream ss;
#ifdef SHOW_TIMING
    struct timeval startTime, endTime;
#endif

    for (auto challenge : challenges) {

        ss.str(std::string());

        const uint8_t* message = reinterpret_cast<const uint8_t*>(challenge.first.c_str());
        size_t len = challenge.first.length();

        //cout << "challenge: " << message << endl;
#ifdef SHOW_TIMING
        gettimeofday(&startTime, NULL);
#endif

        EXPECT_TRUE(strategy.update(message, len));
        ss << strategy.getHash();

#ifdef SHOW_TIMING
        gettimeofday(&endTime, NULL);
        auto time = (endTime.tv_sec + 1e-6 * endTime.tv_usec) - (startTime.tv_sec + 1e-6 * startTime.tv_usec);
        cout << "Time = " << time << "s" << endl;
        cout << "Speed = " << len / time << " bytes/s" << endl;
#endif

        EXPECT_STREQ(challenge.second.c_str(), ss.str().c_str());
    }
}

TEST(BitsRotation, RotateLeftTest)
{
    auto rotate_left = [](auto challenge, auto shift, auto expected) {
        EXPECT_EQ(expected, crypto::utils::rotate_left(challenge, shift));
    };

    rotate_left(0x00F00000UL, 24, 0x0000F00000000000UL);
    rotate_left(0x00F00000UL, 0, 0x00F00000UL);
    rotate_left(0x00F00000UL, sizeof(uint64_t) * 8, 0x00F00000UL);

    rotate_left(0xABCDEF01U, 24, 0x01ABCDEFU);
    rotate_left(0xABCDEF01U, 0, 0xABCDEF01U);
    rotate_left(0xABCDEF01U, sizeof(uint32_t) * 8, 0xABCDEF01U);

    rotate_left(0U, 24, 0U);
    rotate_left(0U, 0, 0U);
    rotate_left(0U, sizeof(uint32_t) * 8, 0U);

    rotate_left(~0U, 24, ~0U);
    rotate_left(~0U, 0, ~0U);
    rotate_left(~0U, sizeof(uint32_t) * 8, ~0U);
}

TEST(BitsRotation, RotateRightTest)
{
    auto rotate_right = [](auto challenge, auto shift, auto expected) {
        EXPECT_EQ(expected, crypto::utils::rotate_right(challenge, shift));
    };

    rotate_right(0x00F00000UL, 24, 0xF000000000000000UL);
    rotate_right(0x00F00000UL, 0, 0x00F00000UL);
    rotate_right(0x00F00000UL, sizeof(uint64_t) * 8, 0x00F00000UL);

    rotate_right(0xABCDEF01U, 24, 0xCDEF01ABU);
    rotate_right(0xABCDEF01U, 0, 0xABCDEF01U);
    rotate_right(0xABCDEF01U, sizeof(uint32_t) * 8, 0xABCDEF01U);

    rotate_right(0U, 24, 0U);
    rotate_right(0U, 0, 0U);
    rotate_right(0U, sizeof(uint32_t) * 8, 0U);

    rotate_right(~0U, 24, ~0U);
    rotate_right(~0U, 0, ~0U);
    rotate_right(~0U, sizeof(uint32_t) * 8, ~0U);
}

TEST(CryptoHash, DisplayHashTest)
{
    std::stringstream ss;

    ss << crypto::CryptoHash<1>{ 0x00 };
    EXPECT_STREQ(ss.str().c_str(), "00");
    ss.str(std::string());

    ss << crypto::CryptoHash<4>{ 0xab, 0xcd, 0xef, 0x12 };
    EXPECT_STREQ(ss.str().c_str(), "abcdef12");
    ss.str(std::string());

    crypto::CryptoHash<20> myhash1;
    myhash1.fill(0x0f);
    ss << myhash1;
    EXPECT_STREQ(ss.str().c_str(), "0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f");
    ss.str(std::string());

    crypto::CryptoHash<4> myhash2;
    myhash2.fill(0x00);
    ss << myhash2;
    EXPECT_STREQ(ss.str().c_str(), "00000000");
    ss.str(std::string());
}

TEST(Hashing, SHA1_Test)
{
    HashChallenges<5> challenges =
    {
        {
            std::make_pair(TestEnvironment::getTxt1(), "a9993e364706816aba3e25717850c26c9cd0d89d"),
            std::make_pair(TestEnvironment::getTxt2(), "54e965b871ef62db46596a9d127d00d58dee6d3a"),
            std::make_pair(TestEnvironment::getTxt3(), "8a1c682f37ef5b18b6f430baab3c471854b45116"),
            std::make_pair(TestEnvironment::getTxt4(), "37e99bd10191bb64a3f1a4831c684fb06f6d0cae"),
            std::make_pair(TestEnvironment::getTxt5(), "cbf749280ee1d843d0f00ffc72da561d9783a7bf")
        }
    };

    hashProve(challenges, crypto::SHA1hashing());
}

TEST(Hashing, SHA224_Test)
{
    HashChallenges<5> challenges =
    {
        {
            std::make_pair(TestEnvironment::getTxt1(), "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"),
            std::make_pair(TestEnvironment::getTxt2(), "af7ecfa6465732c6eb343edc65f8b5e2bcf2758e7cd90c053bc52656"),
            std::make_pair(TestEnvironment::getTxt3(), "cebab609c626ab94f1f6a2d185985d71771c56a7adaa8fca5d6a850d"),
            std::make_pair(TestEnvironment::getTxt4(), "9516d8f203b9f823fa328a45268861ba3b41a18a9d97c4143d446b09"),
            std::make_pair(TestEnvironment::getTxt5(), "7cc6291901247aa33b877a6ef698e38d173ffab1025c7f16cbf55e77")
        }
    };

    hashProve(challenges, crypto::SHA224hashing());
}

TEST(Hashing, SHA256_Test)
{
    HashChallenges<5> challenges =
    {
        {
            std::make_pair(TestEnvironment::getTxt1(), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
            std::make_pair(TestEnvironment::getTxt2(), "73624341c9c85fe7eb6e5de6adddbb87201b6cca5d3ba110ecc3a5a3d6a15470"),
            std::make_pair(TestEnvironment::getTxt3(), "ad8e07b9e9ac103a1bee6bdb86b3f44a5c0c2e0548b13f8da23ebc2b5a128e40"),
            std::make_pair(TestEnvironment::getTxt4(), "3893e51b9249f314120cdf68ccda30bee1b687ec49b19978e72c284e05a91cef"),
            std::make_pair(TestEnvironment::getTxt5(), "9c21dc48134f154838b176df5b05fd614ee91c0719557de1fbbdfa230ec0bae5"),
        }
    };

    hashProve(challenges, crypto::SHA256hashing());
}

TEST(Hashing, SHA384_Test)
{
    HashChallenges<5> challenges =
    {
        {
            std::make_pair(TestEnvironment::getTxt1(), "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"),
            std::make_pair(TestEnvironment::getTxt2(), "c9290606bdc03eb2f698d5f5a3739041bdafc686d9aaf4d55d081644d2c2bf87736f810a9908178ee6f1cd5ff6feecba"),
            std::make_pair(TestEnvironment::getTxt3(), "8bd67f75f21da0d5f04a9c77ceab9897f9dec06710a977ad36cbb29e8d0658ce9042b28429563c62a6c0f847b4f7c81e"),
            std::make_pair(TestEnvironment::getTxt4(), "478599c5d02aff63c7434e03f7db5e9b327184f68a55857ee575c43d255b1529ec214d4c8523cf412bf52f4f34c4ada3"),
            std::make_pair(TestEnvironment::getTxt5(), "2a2b947479430bad4f1ba2140f90eb8e4e53c9ee55dd0be86475093a308e5e5aab3ccfa628afb9bc906d674bcac3ac49")
        }
    };

    hashProve(challenges, crypto::SHA384hashing());
}

TEST(Hashing, SHA512_Test)
{
    HashChallenges<5> challenges =
    {
        {
            std::make_pair(TestEnvironment::getTxt1(), "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"),
            std::make_pair(TestEnvironment::getTxt2(), "5c3ae042ffabd0d90a4d93dbd7bddb1152c0d391898553aa1674fa6df5bcf602791eeb3e9e9aba28ad2a22ebf5443920b1483319269f348410713645c6fc2637"),
            std::make_pair(TestEnvironment::getTxt3(), "338bd5f492d825889b263dfe4d63e9355fff8098c0e5c5f6e0c6a092c07c67a8b3df0e62c21928be592dbd5788bdad4d80df6709ead6a1cd75189a35011ccf86"),
            std::make_pair(TestEnvironment::getTxt4(), "ad61c810586629567d69eaa77c9bc72703de5fe1ffce09b97b701299e0f3d19231c8a0ed05c468df23859a0ba400357542168cde59df45a933d39026abaf7bb9"),
            std::make_pair(TestEnvironment::getTxt6(), "4e56b4ae3437f0290dbc6dc1c4f8bf8ab2749d1f6d9efe041b6a276fc5d8f2cc6750fdfef1bf49a58d84ce6eeaf054e57d7700236ad8fa4129d84cd7291688c6")
        }
    };

    hashProve(challenges, crypto::SHA512hashing());
}

TEST(Hashing, MD4_Test)
{
    HashChallenges<3> challenges =
    {
        std::make_pair(TestEnvironment::getTxt1(), "a448017aaf21d8525fc10ae87aa6729d"),
        std::make_pair(TestEnvironment::getTxt2(), "2d85cb0dfc938572c5b3e8d41b724c55"),
        std::make_pair(TestEnvironment::getTxt3(), "bdbba5cc002c432ac14368c4ac6a03eb")
    };

    hashProve(challenges, crypto::MD4hashing());
}

TEST(Hashing, MD5_Test)
{
    HashChallenges<3> challenges =
    {
        std::make_pair(TestEnvironment::getTxt1(), "900150983cd24fb0d6963f7d28e17f72"),
        std::make_pair(TestEnvironment::getTxt2(), "b9522cae373f305effab33e7e7b72a97"),
        std::make_pair(TestEnvironment::getTxt3(), "47fe7eafa9feb347c9f50f2571f76f06")
    };

    hashProve(challenges, crypto::MD5hashing());
}

int main(int argc, char* argv[]) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
