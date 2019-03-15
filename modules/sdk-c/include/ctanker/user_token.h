#ifndef CTANKER_SDK_USERTOKEN_H
#define CTANKER_SDK_USERTOKEN_H

#include <ctanker/async.h>
#include <ctanker/base64.h>

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*!
 * Generate a new UserToken
 * \param trustchain_id the ID of the trustchain
 * \param trustchain_private_key the Private Key of the trustchain
 * \param user_id the user for whom the token is generated
 * \return an expected (ready future) of base64-encoded user token (b64char*)
 * \post the user token must be freed with tanker_free_buffer()
 */
tanker_expected_t* tanker_generate_user_token(
    b64char const* trustchain_id,
    b64char const* trustchain_private_key,
    char const* user_id);

#ifdef __cplusplus
}
#endif

#endif
