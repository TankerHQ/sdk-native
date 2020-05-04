#ifndef CTANKER_SDK_TANKER_ADMIN_H
#define CTANKER_SDK_TANKER_ADMIN_H

#include <ctanker/admin/export.h>
#include <ctanker/async.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct tanker_app_descriptor
{
  char const* name;
  char const* id;
  char const* auth_token;
  char const* private_key;
  char const* public_key;
} tanker_app_descriptor_t;

typedef struct tanker_admin tanker_admin_t;

/*!
 * Authenticates to the Tanker admin server API
 *
 * \param url The URL of the tanker server to connect to
 * \param id_token The authentication token string for the admin API
 * \return The admin instance. Free with tanker_admin_destroy.
 */
TANKER_ADMIN_C_EXPORT tanker_future_t* tanker_admin_connect(
    char const* url, char const* id_token);

/*!
 * Creates a new app
 *
 * \return The app_descriptor. Free with
 * tanker_admin_app_descriptor_free
 */
TANKER_ADMIN_C_EXPORT tanker_future_t* tanker_admin_create_app(
    tanker_admin_t* admin, char const* name);

/*!
 * Deletes the app permanently
 *
 * \return A future that resolves when the app has been deleted
 */
TANKER_ADMIN_C_EXPORT tanker_future_t* tanker_admin_delete_app(
    tanker_admin_t* admin, char const* app_id);

/*!
 * Frees the app descriptor structure
 */
TANKER_ADMIN_C_EXPORT void tanker_admin_app_descriptor_free(
    tanker_app_descriptor_t* app);

/*!
 * Disconnects and destroys the admin instance.
 *
 * \return A future that resolves when the instance has been deleted.
 */
TANKER_ADMIN_C_EXPORT tanker_future_t* tanker_admin_destroy(
    tanker_admin_t* admin);

/*!
 * Gets verification code of a user from the server
 */
TANKER_ADMIN_C_EXPORT tanker_future_t* tanker_get_verification_code(
    char const* url,
    char const* app_id,
    char const* auth_token,
    char const* user_email);

/*!
 * Updates app properties
 */
TANKER_ADMIN_C_EXPORT tanker_future_t* tanker_admin_app_update(
    tanker_admin_t* admin,
    char const* app_id,
    char const* oidc_client_id,
    char const* oidc_client_provider);

#ifdef __cplusplus
}
#endif

#endif
