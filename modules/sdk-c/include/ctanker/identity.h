#ifndef CTANKER_SDK_IDENTITY_H
#define CTANKER_SDK_IDENTITY_H

#include <ctanker/async.h>
#include <ctanker/base64.h>

#ifdef __cplusplus
extern "C" {
#endif

/*!
 * Generate a new Identity
 * \param trustchain_id the ID of the trustchain
 * \param trustchain_private_key the private key of the trustchain
 * \param user_id the user for whom the token is generated
 * \return an expected (ready future) of base64-encoded identity (b64char*)
 * \post the identity must be freed with tanker_free_buffer()
 */
tanker_expected_t* tanker_create_identity(b64char const* trustchain_id,
                                          b64char const* trustchain_private_key,
                                          char const* user_id);

/*!
 * Upgrade a UserToken to an Identity
 * \param trustchain_id the ID of the trustchain
 * \param user_id the user for whom the token is upgraded
 * \param user_token the user token you want to upgrade
 * \return an expected of base64-encoded identity (b64char*)
 * \post the identity must be freed with tanker_free_buffer()
 * \throws TANKER_INVALID_ARGUMENT if the wrong userId is provided
 */
tanker_expected_t* tanker_upgrade_user_token(b64char const* trustchain_id,
                                             char const* user_id,
                                             b64char const* user_token);

/*!
 * Get a Public Identity from an Identity
 * \param identity the identity token
 * \return an expected (ready future) of base64-encoded public identity
 * (b64char*)
 * \post the public identity must be freed with tanker_free_buffer()
 */
tanker_expected_t* tanker_get_public_identity(b64char const* identity);
#ifdef __cplusplus
}
#endif

#endif