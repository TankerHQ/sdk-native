#ifndef CTANKER_SDK_TANKER_ADMIN_H
#define CTANKER_SDK_TANKER_ADMIN_H

#include <ctanker/async.h>
#include <ctanker/base64.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct tanker_trustchain_descriptor
{
  char const* name;
  b64char const* id;
  b64char const* private_key;
  b64char const* public_key;
} tanker_trustchain_descriptor_t;

typedef struct tanker_admin tanker_admin_t;

/*!
 * Authenticates to the Tanker admin server API
 *
 * \param trustchain_url The URL of the tanker server to connect to
 * \param id_token The authentication token string for the admin API
 * \return The admin instance. Free with tanker_admin_destroy.
 */
tanker_future_t* tanker_admin_connect(char const* trustchain_url,
                                      char const* id_token);

/*!
 * Creates a new trustchain
 *
 * \return The trustchain_descriptor. Free with tanker_admin_trustchain_descriptor_free
 */
tanker_future_t* tanker_admin_create_trustchain(tanker_admin_t* admin,
                                                char const* name);

/*!
 * Deletes the trustchain permanently
 *
 * \return A future that resolves when the trustchain has been deleted
 */
tanker_future_t* tanker_admin_delete_trustchain(tanker_admin_t* admin,
                                                char const* trustchain_id);

/*!
 * Frees the trustchain descriptor structure
 */
void tanker_admin_trustchain_descriptor_free(
    tanker_trustchain_descriptor_t* trustchain);

/*!
 * Disconnects and destroys the admin instance.
 *
 * \return A future that resolves when the instance has been deleted.
 */
tanker_future_t* tanker_admin_destroy(tanker_admin_t* admin);

/*!
 * Gets verification code of a user from the server
 */
tanker_future_t* tanker_admin_get_verification_code(
    tanker_admin_t* admin, char const* trustchain_id, char const* user_email);


#ifdef __cplusplus
}
#endif

#endif // CTANKER_SDK_TANKER_ADMIN_H
