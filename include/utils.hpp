#ifndef _CRYPTO_UTILS_HPP
#define _CRYPTO_UTILS_HPP

#include <cstdint>

namespace crypto {
namespace utils {

/* Circular left shift of x of n bits.
 **/
template <typename T>
inline T rotate_left(const T& x, uint8_t n);

/* Circular right shift of x of n bits.
 **/
template <typename T>
inline T rotate_right(const T& x, uint8_t n);

} /* namespace utils */
} /* namespace crypto */

#include "utils.ipp"

#endif /* _CRYPTO_UTILS_HPP */
