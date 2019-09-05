#ifndef CTANKER_SDK_TANKER_ADMIN_H
#define CTANKER_SDK_TANKER_ADMIN_H

#include <ctanker/async.h>
#include <ctanker/base64.h>
#include <ctanker/admin/export.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct tanker_app_descriptor
{
  char const* name;
  b64char const* id;
  b64char const* private_key;
  b64char const* public_key;
} tanker_app_descriptor_t;

typedef struct tanker_admin tanker_admin_t;

/*!
 * Authenticates to the Tanker admin server API
 *
 * \param url The URL of the tanker server to connect to
 * \param id_token The authentication token string for the admin API
 * \return The admin instance. Free with tanker_admin_destroy.
 */
CTANKER_EXPORT tanker_future_t* tanker_admin_connect(char const* url,
                                                     char const* id_token);

/*!
 * Creates a new app
 *
 * \return The app_descriptor. Free with
 * tanker_admin_app_descriptor_free
 */
CTANKER_EXPORT tanker_future_t* tanker_admin_create_app(tanker_admin_t* admin,
                                                        char const* name);

/*!
 * Deletes the app permanently
 *
 * \return A future that resolves when the app has been deleted
 */
CTANKER_EXPORT tanker_future_t* tanker_admin_delete_app(tanker_admin_t* admin,
                                                        char const* app_id);

/*!
 * Frees the app descriptor structure
 */
CTANKER_EXPORT void tanker_admin_app_descriptor_free(
    tanker_app_descriptor_t* app);

/*!
 * Disconnects and destroys the admin instance.
 *
 * \return A future that resolves when the instance has been deleted.
 */
CTANKER_EXPORT tanker_future_t* tanker_admin_destroy(tanker_admin_t* admin);

/*!
 * Gets verification code of a user from the server
 */
CTANKER_EXPORT tanker_future_t* tanker_admin_get_verification_code(
    tanker_admin_t* admin, char const* app_id, char const* user_email);

#ifdef __cplusplus
}
#endif

#endif // CTANKER_SDK_TANKER_ADMIN_H
