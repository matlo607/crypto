#include <utility>
#include <cassert>

namespace crypto {
namespace utils {

/* Circular left shift of x of n bits.
 **/
template <typename T>
inline T rotate_left(const T& x, uint8_t n)
{
    assert(n <= sizeof(T) * 8);
    T rotated = (x << n) | (x >> (sizeof(T) * 8 - n));
    return rotated;
}

/* Circular right shift of x of n bits.
 **/
template <typename T>
inline T rotate_right(const T& x, uint8_t n)
{
    assert(n <= sizeof(T) * 8);
    T rotated = (x >> n) | (x << (sizeof(T) * 8 - n));
    return rotated;
}

} /* namespace utils */
} /* namespace crypto */

