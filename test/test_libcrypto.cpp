#include "gtest/gtest.h"

#include "utils.hpp"
#include "HashingStrategy.hpp"
#include "SHA1.hpp"
#include "SHA256.hpp"
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

        virtual void SetUp() { }
};

using crypto::operator<<;

template <size_t N>
using HashChallenges = std::array< std::pair<const std::string, const std::string>, N >;

template <size_t N_challenges, size_t N_hashSize, size_t N_blockSize>
void hashProve(HashChallenges<N_challenges>& challenges, crypto::HashingStrategy<N_hashSize,N_blockSize>&& strategy)
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
    HashChallenges<3> challenges =
    {
        {
            std::make_pair(TestEnvironment::getTxt1(), "a9993e364706816aba3e25717850c26c9cd0d89d"),
            std::make_pair(TestEnvironment::getTxt2(), "54e965b871ef62db46596a9d127d00d58dee6d3a"),
            std::make_pair(TestEnvironment::getTxt3(), "8a1c682f37ef5b18b6f430baab3c471854b45116")
        }
    };

    hashProve(challenges, crypto::SHA1hashing());
}

TEST(Hashing, SHA256_Test)
{
    HashChallenges<3> challenges =
    {
        {
            std::make_pair(TestEnvironment::getTxt1(), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
            std::make_pair(TestEnvironment::getTxt2(), "73624341c9c85fe7eb6e5de6adddbb87201b6cca5d3ba110ecc3a5a3d6a15470"),
            std::make_pair(TestEnvironment::getTxt3(), "ad8e07b9e9ac103a1bee6bdb86b3f44a5c0c2e0548b13f8da23ebc2b5a128e40")
        }
    };

    hashProve(challenges, crypto::SHA256hashing());
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
