#ifndef CTANKER_SDK_IDENTITY_H
#define CTANKER_SDK_IDENTITY_H

#include <ctanker/async.h>
#include <ctanker/base64.h>
#include <ctanker/export.h>

#ifdef __cplusplus
extern "C" {
#endif

/*!
 * Generate a new Tanker identity
 * \param app_id the ID of the app
 * \param app_secret the secret of the app
 * \param user_id the user for whom the identity is generated
 * \return an expected (ready future) of base64-encoded identity (b64char*)
 * \post the identity must be freed with tanker_free_buffer()
 */
CTANKER_EXPORT tanker_expected_t* tanker_create_identity(
    b64char const* app_id, b64char const* app_secret, char const* user_id);

/*!
 * Generate a new Tanker provisional identity
 * \param app_id the ID of the app
 * \param email the email address for whom the identity is generated
 * \return an expected (ready future) of base64-encoded identity (b64char*)
 * \post the identity must be freed with tanker_free_buffer()
 */
CTANKER_EXPORT tanker_expected_t* tanker_create_provisional_identity(
    b64char const* app_id, char const* email);

/*!
 * Upgrade a UserToken to an Identity
 * \param app_id the ID of the app
 * \param user_id the user for whom the token is upgraded
 * \param user_token the user token you want to upgrade
 * \return an expected of base64-encoded identity (b64char*)
 * \post the identity must be freed with tanker_free_buffer()
 * \throws TANKER_INVALID_ARGUMENT if the wrong userId is provided
 */
CTANKER_EXPORT tanker_expected_t* tanker_upgrade_user_token(
    b64char const* app_id, char const* user_id, b64char const* user_token);

/*!
 * Get a Public Identity from an Identity
 * \param identity the identity token
 * \return an expected (ready future) of base64-encoded public identity
 * (b64char*)
 * \post the public identity must be freed with tanker_free_buffer()
 */
CTANKER_EXPORT tanker_expected_t* tanker_get_public_identity(
    b64char const* identity);
#ifdef __cplusplus
}
#endif

#endif
