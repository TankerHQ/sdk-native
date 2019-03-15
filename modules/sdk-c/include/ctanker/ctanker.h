#ifndef CTANKER_SDK_TANKER_TANKER_H
#define CTANKER_SDK_TANKER_TANKER_H

#include <ctanker/async.h>
#include <ctanker/base64.h>

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum tanker_status
{
  TANKER_STATUS_CLOSED,
  TANKER_STATUS_OPEN,

  TANKER_STATUS_LAST
};

enum tanker_sign_in_result
{
  TANKER_SIGN_IN_RESULT_OK,
  TANKER_SIGN_IN_RESULT_IDENTITY_NOT_REGISTERED,
  TANKER_SIGN_IN_RESULT_IDENTITY_VERIFICATION_NEEDED,

  TANKER_SIGN_IN_RESULT_LAST,
};

enum tanker_event
{
  TANKER_EVENT_SESSION_CLOSED,
  TANKER_EVENT_DEVICE_CREATED,
  TANKER_EVENT_DEVICE_REVOKED,

  TANKER_EVENT_LAST,
};

enum tanker_unlock_method
{
  TANKER_UNLOCK_METHOD_EMAIL = 0x1,
  TANKER_UNLOCK_METHOD_PASSWORD = 0x2,

  TANKER_UNLOCK_METHOD_LAST = TANKER_UNLOCK_METHOD_PASSWORD
};

typedef struct tanker tanker_t;
typedef struct tanker_options tanker_options_t;
typedef struct tanker_authentication_methods tanker_authentication_methods_t;
typedef struct tanker_sign_in_options tanker_sign_in_options_t;
typedef struct tanker_encrypt_options tanker_encrypt_options_t;

/*!
 * \brief Callback type to filter Tanker SDK logs.
 * \discussion Should be used with tanker_set_log_handler.
 *
 * \param category a string describing the log's category
 * \param level the level of priority of the message.
 *        (Either 'I' for info, 'E' for error or 'D' for debug)
 * \param message the message to log.
 */
typedef void (*tanker_log_handler_t)(char const* category,
                                     char level,
                                     char const* message);

typedef struct tanker_connection tanker_connection_t;
typedef void (*tanker_event_callback_t)(void* arg, void* data);

/*!
 * Options used to create a tanker instance.
 */
struct tanker_options
{
  uint8_t version;
  b64char const* trustchain_id; /*!< Must not be NULL. */
  char const* trustchain_url;   /*!< Must not be NULL. */
  char const* writable_path;    /*!< Must not be NULL. */
  char const* sdk_type;         /*!< Must not be NULL. */
  char const* sdk_version;      /*!< Must not be NULL. */
};

#define TANKER_OPTIONS_INIT         \
  {                                 \
    2, NULL, NULL, NULL, NULL, NULL \
  }

struct tanker_authentication_methods
{
  uint8_t version;
  char const* password;
  char const* email;
};

#define TANKER_AUTHENTICATION_METHODS_INIT \
  {                                        \
    1, NULL, NULL                          \
  }

struct tanker_sign_in_options
{
  uint8_t version;
  char const* unlock_key;
  char const* verification_code;
  char const* password;
};

#define TANKER_SIGN_IN_OPTIONS_INIT \
  {                                 \
    1, NULL, NULL, NULL             \
  }

struct tanker_encrypt_options
{
  uint8_t version;
  b64char const* const* recipient_public_identities;
  uint32_t nb_recipient_public_identities;
  b64char const* const* recipient_gids;
  uint32_t nb_recipient_gids;
};

#define TANKER_ENCRYPT_OPTIONS_INIT \
  {                                 \
    2, NULL, 0, NULL, 0             \
  }

/*!
 * Allow to access version.
 * \return The current version of Tanker as a string.
 */
char const* tanker_version_string(void);

/*!
 * Set the log handler of the API with a function pointer
 * \param handler the function pointer, it must have the prototype of
 *        tanker_log_handler_t.
 */
void tanker_set_log_handler(tanker_log_handler_t handler);

/*!
 * Initialize the SDK
 */
void tanker_init(void);

/*!
 * Create a Tanker instance.
 * \param options struct tanker_options_t with the following preconditions.
 * \pre The *option* structure must not be NULL, as well as the fields
 *      specified in its documentation.
 * \return A tanker_future of a tanker_t*
 * \throws TANKER_ERROR_INVALID_ARGUMENT \p options is NULL, or lacks mandatory
 *         fields, or has malformed fields
 */
tanker_future_t* tanker_create(tanker_options_t const* options);

/*!
 * Destroy a tanker instance.
 * \param tanker a tanker tanker_t* to be deleted.
 * \pre The tanker parameter has been allocated.
 * \return an async future.
 */
tanker_future_t* tanker_destroy(tanker_t* tanker);

/*!
 * Connect to an event.
 * \param tanker A tanker tanker_t* instance.
 * \param event The event to connect.
 * \param data The data to pass to the callback.
 * \return an expected of a tanker_connection_t* that must be disconnected with
 * tanker_event_disconnect().
 * \throws TANKER_ERROR_INVALID_ARGUMENT \p event does not exist
 */
tanker_expected_t* tanker_event_connect(tanker_t* tanker,
                                        enum tanker_event event,
                                        tanker_event_callback_t cb,
                                        void* data);

/*!
 * Disconnect from an event.
 * \param tanker is not yet used.
 * \param connection a tanker_connection_t* to disconnect from.
 * \return an expected of NULL.
 */
tanker_expected_t* tanker_event_disconnect(tanker_t* tanker,
                                           tanker_connection_t* connection);

/*!
 * Sign up to Tanker.
 *
 * \param tanker a tanker tanker_t* instance.
 * \param identity the user identity.
 * \param authentication_methods the authentication methods to set up for the
 * user, or NULL.
 * \return a future of NULL
 * \throws TANKER_ERROR_INVALID_ARGUMENT \p indentity is NULL
 * \throws TANKER_ERROR_OTHER could not connect to the Tanker server
 * or the server returned an error
 * \throws TANKER_ERROR_OTHER could not open the local storage
 */
tanker_future_t* tanker_sign_up(
    tanker_t* tanker,
    char const* identity,
    tanker_authentication_methods_t const* authentication_methods);

/*!
 * Sign in to Tanker.
 *
 * \param tanker a tanker tanker_t* instance.
 * \param identity the user identity.
 * \param sign_in_options the authentication options to use when this device is
 * not registered, or NULL.
 * \return a future of tanker_sign_in_result
 * \throws TANKER_ERROR_INVALID_ARGUMENT \p indentity is NULL
 * \throws TANKER_ERROR_INVALID_UNLOCK_KEY unlock key is incorrect
 * \throws TANKER_ERROR_INVALID_VERIFICATION_CODE verification code is incorrect
 * \throws TANKER_ERROR_INVALID_UNLOCK_PASSWORD password is incorrect
 * \throws TANKER_ERROR_OTHER could not connect to the Tanker server
 * or the server returned an error
 * \throws TANKER_ERROR_OTHER could not open the local storage
 */
tanker_future_t* tanker_sign_in(
    tanker_t* tanker,
    char const* identity,
    tanker_sign_in_options_t const* sign_in_options);

/*!
 * Close a tanker session.
 * \param tanker A tanker tanker_t* instance.
 * \pre tanker must be allocated with tanker_create().
 * \pre tanker must be opened with tanker_open().
 */
tanker_future_t* tanker_sign_out(tanker_t* tanker);

/*!
 * Get the status of the tanker instance.
 * \param tanker A tanker tanker_t* instance.
 * \pre tanker must be allocated with tanker_create().
 * \return the tanker status.
 */
enum tanker_status tanker_get_status(tanker_t* tanker);

/*!
 * Get the current device id.
 * \param session A tanker_t* instance.
 * \pre tanker_status == TANKER_STATUS_OPEN
 * \return a future of b64char* that must be freed with tanker_free_buffer.
 */
tanker_future_t* tanker_device_id(tanker_t* session);

/*!
 * Generate an unlockKey that can be used to accept a device
 * \param session A tanker tanker_t* instance
 * \pre tanker_status == TANKER_STATUS_OPEN
 * \return a future of b64char* that must be freed with tanker_free_buffer
 * \throws TANKER_ERROR_OTHER could not connect to the Tanker server or the
 * server returned an error
 */
tanker_future_t* tanker_generate_and_register_unlock_key(tanker_t* session);

/*!
 * Registers, or updates, the user's unlock claims,
 * creates an unlock key if necessary
 * \param session a tanker tanker_t* instance
 * \param new_email the new desired email
 * \param new_password the new desired password
 * \pre tanker_status == TANKER_STATUS_OPEN
 * \return a future to void
 */
tanker_future_t* tanker_register_unlock(tanker_t* session,
                                        char const* new_email,
                                        char const* new_password);

/*!
 * Unlock the current device with the previously set-up unlock key
 * \param session a tanker tanker_t* instance
 * \param pass the password previously given for the unlock key protection
 * \pre tanker_status == TANKER_STATUS_DEVICE_CREATION
 * \return a future to void
 */
tanker_future_t* tanker_unlock_current_device_with_password(tanker_t* session,
                                                            char const* pass);

/*!
 * Unlock the current device with the previously set-up unlock key
 * \param session a tanker tanker_t* instance
 * \param verification_code the verification code sent to the email previously
 * given for the unlock key protection
 * \pre tanker_status == TANKER_STATUS_DEVICE_CREATION
 * \return a future to void
 */
tanker_future_t* tanker_unlock_current_device_with_verification_code(
    tanker_t* session, char const* verification_code);

/*!
 * Unlock this device with the user's unlockKey.
 * \param session A tanker tanker_t* instance.
 * \pre tanker_status == TANKER_STATUS_DEVICE_CREATION
 * \param unlock_key The user's unlock_key
 * \throws TANKER_ERROR_INVALID_UNLOCK_KEY if the unlockKey format or the key
 * itself is incorrect
 * \throws TANKER_ERROR_OTHER could not connect to the
 * Tanker server or the server returned an error
 */
tanker_future_t* tanker_unlock_current_device_with_unlock_key(
    tanker_t* session, b64char const* unlock_key);

/*!
 * Check if unlock mechanism has been set up for the current user.
 * \param session A tanker tanker_t* instance.
 * \pre tanker_status == TANKER_STATUS_OPEN
 * \return true if an unlock mechanism is already set up, false otherwise
 */
tanker_future_t* tanker_is_unlock_already_set_up(tanker_t* session);

/*!
 * Return all registered unlock methods for the current user.
 * \param session A tanker tanker_t* instance.
 * \pre tanker_status == TANKER_STATUS_OPEN
 * \return a tanker_unlock_method with its bit set to the registered methods
 */
tanker_expected_t* tanker_registered_unlock_methods(tanker_t* session);

/*!
 * Check if any unlock methods has been registered for the current user.
 * \param session A tanker tanker_t* instance.
 * \pre tanker_status == TANKER_STATUS_OPEN
 * \return true if an unlock method is registered, false otherwise
 */
tanker_expected_t* tanker_has_registered_unlock_methods(tanker_t* session);

/*!
 * Check if a specific unlock method has been registered for the current user.
 * \param session A tanker tanker_t* instance.
 * \param method the unlock method we want to test.
 * \pre tanker_status == TANKER_STATUS_OPEN
 * \return true if an unlock method is registered, false otherwise
 */
tanker_expected_t* tanker_has_registered_unlock_method(
    tanker_t* session, enum tanker_unlock_method method);

/*!
 * Get the encrypted size from the clear size.
 * Must be called before encrypt to allocate the encrypted buffer.
 */
uint64_t tanker_encrypted_size(uint64_t clear_size);

/*!
 * Get the decrypted size.
 *
 * Must be called before decrypt to allocate the decrypted buffer.
 *
 * \return The size the decrypted data would take, cast to a void*, or an
 * error if the data is corrupted.
 * \throws TANKER_ERROR_DECRYPT_FAILED the
 * buffer is corrupt or truncated
 */
tanker_expected_t* tanker_decrypted_size(uint8_t const* encrypted_data,
                                         uint64_t encrypted_size);

/*!
 * Get the resource id from an encrypted data.
 * \return an already ready future of a string.
 */
tanker_expected_t* tanker_get_resource_id(uint8_t const* encrypted_data,
                                          uint64_t encrypted_size);

/*!
 * Encrypt data.
 * \param tanker A tanker tanker_t* instance.
 * \pre tanker_status == TANKER_STATUS_OPEN
 * \param encrypted_data The container for the encrypted data.
 * \pre encrypted_data must be allocated with a call to
 *      tanker_encrypted_size() in order to get the size beforehand.
 * \param data The array of bytes to encrypt.
 * \pre data_size must be the size of the *data* parameter
 *
 * \return An empty future.
 * \throws TANKER_ERROR_USER_NOT_FOUND at least one user to share with was not
 * found
 * \throws TANKER_ERROR_OTHER could not connect to the Tanker server or the
 * server returned an error
 */
tanker_future_t* tanker_encrypt(tanker_t* tanker,
                                uint8_t* encrypted_data,
                                uint8_t const* data,
                                uint64_t data_size,
                                tanker_encrypt_options_t const* options);

/*!
 * Decrypt an encrypted data.
 *
 * \param session A tanker tanker_t* instance.
 * \pre tanker_status == TANKER_STATUS_OPEN
 * \param decrypted_data Decrypted array of bytes.
 * \pre decrypted_data must be allocated with a call to
 *      tanker_decrypted_size() in order to get the size beforehand.
 * \param data Array of bytes to decrypt.
 * \param data_size Size of the \p data argument.
 *
 * \return An empty future.
 * \throws TANKER_ERROR_DECRYPT_FAILED The buffer was corrupt or truncated
 * \throws TANKER_ERROR_RESOURCE_KEY_NOT_FOUND The key was not found
 */
tanker_future_t* tanker_decrypt(tanker_t* session,
                                uint8_t* decrypted_data,
                                uint8_t const* data,
                                uint64_t data_size);

/*!
 * Share a symetric key of an encrypted data with other users.
 *
 * \param session A tanker tanker_t* instance.
 * \pre tanker_status == TANKER_STATUS_OPEN
 * \param recipient_public_identities Array of strings describing the user
 * recipients.
 * \param nb_recipient_public_identities The number of recipients in
 * recipient_public_identities.
 * \param recipient_gids Array of strings describing the group recipients.
 * \param nb_recipient_gids The number of recipients in recipient_gids.
 * \param resource_ids Array of string describing the resources.
 * \param nb_resource_ids The number of resources in resource_ids.
 *
 * \return An empty future.
 * \throws TANKER_ERROR_RECIPIENT_NOT_FOUND One of the recipients was not found,
 * no action was done
 * \throws TANKER_ERROR_RESOURCE_KEY_NOT_FOUND One of the
 * resource keys was not found, no action was done
 * \throws TANKER_ERROR_OTHER could not connect to the Tanker server or the
 * server returned an error
 */
tanker_future_t* tanker_share(tanker_t* session,
                              char const* const* recipient_public_identities,
                              uint64_t nb_recipient_public_identities,
                              char const* const* recipient_gids,
                              uint64_t nb_recipient_gids,
                              b64char const* const* resource_ids,
                              uint64_t nb_resource_ids);

/*!
 * Revoke a device by device id.
 *
 * \param session A tanker tanker_t* instance.
 * \pre tanker_status == TANKER_STATUS_OPEN
 * \param device_id the device identifier as returned by tanker_device_id().
 *
 * \return An empty future.
 * \throws TANKER_DEVICE_NOT_FOUND The device_id in parameter does not
 * corresponds to a valid device
 * \throws TANKER_INVALID_ARGUMENT The device_id in parameter correspond to
 * another user's device.
 */
tanker_future_t* tanker_revoke_device(tanker_t* session,
                                      b64char const* device_id);

void tanker_free_buffer(void* buffer);

#ifdef __cplusplus
}
#endif

#endif
