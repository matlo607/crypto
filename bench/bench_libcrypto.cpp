#include "MD4.hpp"
#include "MD5.hpp"
#include "SHA1.hpp"
#include "SHA224.hpp"
#include "SHA256.hpp"
#include "SHA384.hpp"
#include "SHA512.hpp"

#include <gsl/span>
#include <string>
#include <iostream>
#include <fstream>
#include <sys/time.h>

#include <openssl/sha.h>

using namespace std;
using crypto::operator<<;

/*
//#define SHOW_TIMING


template <size_t N>
using HashChallenges = std::array< std::pair<const std::string, const std::string>, N >;

template <size_t N_tmpdigest, size_t N_digest = N_tmpdigest, typename T_subTypeBlock = uint32_t, size_t N_blockSize = 64>
using HS = crypto::HashingStrategy<N_tmpdigest, N_digest, T_subTypeBlock, N_blockSize>;

template <size_t N_challenges, size_t N_tmpdigest, size_t N_digest, typename T_subTypeBlock, size_t N_blockSize>
void hashProve(HashChallenges<N_challenges>& challenges, HS<N_tmpdigest, N_digest, T_subTypeBlock, N_blockSize>&& strategy)
{
    std::stringstream ss;
#ifdef SHOW_TIMING
    struct timeval startTime, endTime;
#endif

    for (auto challenge : challenges) {

        ss.str(std::string());

        const uint8_t *p = reinterpret_cast<const uint8_t*>(challenge.first.c_str());
        const ssize_t len = challenge.first.length();
        gsl::span<const uint8_t> message {p, len};

#ifdef SHOW_TIMING
        gettimeofday(&startTime, NULL);
#endif

        EXPECT_TRUE(strategy.update(message));
        ss << gsl::span<const uint8_t>(strategy.getHash());

#ifdef SHOW_TIMING
        gettimeofday(&endTime, NULL);
        auto time = (endTime.tv_sec + 1e-6 * endTime.tv_usec) - (startTime.tv_sec + 1e-6 * startTime.tv_usec);
        cout << "Time = " << time << "s" << endl;
        cout << "Speed = " << len / time << " bytes/s" << endl;
#endif

        EXPECT_STREQ(challenge.second.c_str(), ss.str().c_str());
    }
}*/

int main(int argc, char* argv[])
{
    (void) argc;
    string filename(argv[0]);

    ifstream is (filename.c_str(), ifstream::binary);
    if (is) {
        // get length of file:
        is.seekg (0, is.end);
        ssize_t file_length = is.tellg();
        is.seekg (0, is.beg);

        cout << filename << ": " << file_length << "B"<< endl;

        char buffer[4096];
        crypto::SHA1hashing newlib_context;

        SHA_CTX sha1_context;
        SHA_Init(&sha1_context);

        while (is) {
            is.read (buffer, 4096);

            gsl::span<const uint8_t> message {reinterpret_cast<const uint8_t*>(buffer), is.gcount()};

            newlib_context.update(message);

            SHA_Update(&sha1_context, message.data(), message.size());
        }

        cout << "hash: " << gsl::span<const uint8_t>(newlib_context.getHash()) << endl;

        uint8_t sha1sum[20];
        SHA_Final(sha1sum, &sha1_context);
        cout << "hash: " << gsl::span<const uint8_t>{sha1sum,20};

        is.close();
    }

    return 0;
}
