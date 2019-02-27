#ifndef CTANKER_SDK_TANKER_BASE64_H
#define CTANKER_SDK_TANKER_BASE64_H

#include <stdint.h>

#include <ctanker/async.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef char b64char;

/*!
 * Get the size of a base64 encoded buffer given a buffer of \p decoded_size.
 */
uint64_t tanker_base64_encoded_size(uint64_t decoded_size);

/*!
 * Get the maximum decoded size possible from the size of the encoded data.
 */
uint64_t tanker_base64_decoded_max_size(uint64_t encoded_size);

/*!
 * Encode in base64 the buffer
 * \param to buffer to fill with the encoded data.
 * \pre to buffer must have been allocated with at least the size returned by
 *      the tanker_base64_encoded_size() function.
 * \param from buffer to encode
 * \pre from_size must be the size of the from parameter
 */
void tanker_base64_encode(b64char* to, void const* from, uint64_t from_size);

/*!
 * Decode the buffer with a base64
 * \param to buffer to fill with the decoded datas.
 * \pre to buffer must have been allocated with the size returned by the
 *      tanker_base64_decoded_size() function.
 * \param from buffer to decode
 * \pre from_size must be the size of the from parameter
 * \return an empty expected.
 */
tanker_expected_t* tanker_base64_decode(void* to,
                                        uint64_t* to_size,
                                        b64char const* from,
                                        uint64_t from_size);

#ifdef __cplusplus
}
#endif

#endif
