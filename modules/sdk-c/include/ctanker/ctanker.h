#ifndef CTANKER_SDK_TANKER_TANKER_H
#define CTANKER_SDK_TANKER_TANKER_H

#include <ctanker/async.h>
#include <ctanker/export.h>

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum tanker_status
{
  TANKER_STATUS_STOPPED,
  TANKER_STATUS_READY,
  TANKER_STATUS_IDENTITY_REGISTRATION_NEEDED,
  TANKER_STATUS_IDENTITY_VERIFICATION_NEEDED,

  TANKER_STATUS_LAST
};

enum tanker_event
{
  TANKER_EVENT_SESSION_CLOSED,
  TANKER_EVENT_DEVICE_REVOKED,

  TANKER_EVENT_LAST,
};

enum tanker_verification_method_type
{
  TANKER_VERIFICATION_METHOD_EMAIL = 0x1,
  TANKER_VERIFICATION_METHOD_PASSPHRASE,
  TANKER_VERIFICATION_METHOD_VERIFICATION_KEY,
  TANKER_VERIFICATION_METHOD_OIDC_ID_TOKEN,

  TANKER_VERIFICATION_METHOD_LAST = TANKER_VERIFICATION_METHOD_OIDC_ID_TOKEN
};

enum tanker_log_level
{
  TANKER_LOG_DEBUG = 1,
  TANKER_LOG_INFO,
  TANKER_LOG_WARNING,
  TANKER_LOG_ERROR,
};

typedef struct tanker tanker_t;
typedef struct tanker_options tanker_options_t;
typedef struct tanker_email_verification tanker_email_verification_t;
typedef struct tanker_verification tanker_verification_t;
typedef struct tanker_verification_method tanker_verification_method_t;
typedef struct tanker_encrypt_options tanker_encrypt_options_t;
typedef struct tanker_log_record tanker_log_record_t;
typedef struct tanker_device_list_elem tanker_device_list_elem_t;
typedef struct tanker_device_list tanker_device_list_t;
typedef struct tanker_verification_method_list
    tanker_verification_method_list_t;
typedef struct tanker_attach_result tanker_attach_result_t;

/*!
 * \brief The list of a user's devices
 */
struct tanker_device_list
{
  tanker_device_list_elem_t* devices;
  uint32_t count;
};

/*!
 * \brief Describes one device belonging to the user
 */
struct tanker_device_list_elem
{
  char const* device_id;
  bool is_revoked;
};

/*!
 * \brief The list of a user verification methods
 */
struct tanker_verification_method_list
{
  tanker_verification_method_t* methods;
  uint32_t count;
};

/*!
 * \brief a struct describing a log message
 */
struct tanker_log_record
{
  char const* category;
  uint32_t level;
  char const* file;
  uint32_t line;
  char const* message;
};

/*!
 * \brief Callback type to filter Tanker SDK logs.
 * \discussion Should be used with tanker_set_log_handler.
 *
 * \param record a struct containing all message informations
 */
typedef void (*tanker_log_handler_t)(tanker_log_record_t const* record);

/*!
 * \brief Callback for event notification
 * \param arg the event parameter if any
 * \param data the data pointer to tanker_event_connect
 */
typedef void (*tanker_event_callback_t)(void* arg, void* data);

/*!
 * Options used to create a tanker instance.
 */
struct tanker_options
{
  uint8_t version;
  char const* app_id;        /*!< Must not be NULL. */
  char const* url;           /*!< Must not be NULL. */
  char const* writable_path; /*!< Must not be NULL. */
  char const* sdk_type;      /*!< Must not be NULL. */
  char const* sdk_version;   /*!< Must not be NULL. */
};

#define TANKER_OPTIONS_INIT         \
  {                                 \
    2, NULL, NULL, NULL, NULL, NULL \
  }

struct tanker_email_verification
{
  uint8_t version;
  char const* email;
  char const* verification_code;
};

#define TANKER_EMAIL_VERIFICATION_INIT \
  {                                    \
    1, NULL, NULL                      \
  }

struct tanker_verification
{
  uint8_t version;
  // enum cannot be bound to java as they do not have a fixed size.
  // It takes a value from tanker_verification_method_type:
  uint8_t verification_method_type;
  char const* verification_key;
  tanker_email_verification_t email_verification;
  char const* passphrase;
  char const* oidc_id_token;
};

#define TANKER_VERIFICATION_INIT                           \
  {                                                        \
    3, 0, NULL, TANKER_EMAIL_VERIFICATION_INIT, NULL, NULL \
  }

struct tanker_verification_method
{
  uint8_t version;
  // enum cannot be bound to java as they do not have a fixed size.
  // It takes a value from tanker_verification_method_type:
  uint8_t verification_method_type;
  char const* email;
};

#define TANKER_VERIFICATION_METHOD_INIT \
  {                                     \
    1, 0, NULL                          \
  }

struct tanker_encrypt_options
{
  uint8_t version;
  char const* const* recipient_public_identities;
  uint32_t nb_recipient_public_identities;
  char const* const* recipient_gids;
  uint32_t nb_recipient_gids;
};

#define TANKER_ENCRYPT_OPTIONS_INIT \
  {                                 \
    2, NULL, 0, NULL, 0             \
  }

/*!
 * \brief a struct containing the result of an attach_provisional_identity()
 * If the status is TANKER_STATUS_READY, the method will be default initialized
 * with the values in TANKER_VERIFICATION_METHOD_INIT
 */
struct tanker_attach_result
{
  uint8_t version;
  // enum cannot be bound to java as they do not have a fixed size.
  // It takes a value from the enum tanker_status:
  uint8_t status;
  tanker_verification_method_t* method;
};

#define TANKER_ATTACH_RESULT_INIT \
  {                               \
    1, 0, NULL                    \
  }

/*!
 * Allow to access version.
 * \return The current version of Tanker as a string.
 */
CTANKER_EXPORT char const* tanker_version_string(void);

/*!
 * Set the log handler of the API with a function pointer
 * \param handler the function pointer, it must have the prototype of
 *        tanker_log_handler_t.
 *
 * This function is not thread-safe. Also it must not be called after at least
 * one Tanker has been instantiated.
 */
CTANKER_EXPORT void tanker_set_log_handler(tanker_log_handler_t handler);

/*!
 * Initialize the SDK
 */
CTANKER_EXPORT void tanker_init(void);

/*!
 * Create a Tanker instance.
 * \param options struct tanker_options_t with the following preconditions.
 * \pre The *option* structure must not be NULL, as well as the fields
 *      specified in its documentation.
 * \return A tanker_future of a tanker_t*.
 * \throws TANKER_ERROR_INVALID_ARGUMENT \p options is NULL, or lacks mandatory
 *         fields, or has malformed fields.
 */
CTANKER_EXPORT tanker_future_t* tanker_create(tanker_options_t const* options);

/*!
 * Destroy a tanker instance.
 * \param tanker a tanker tanker_t* to be deleted.
 * \pre The tanker parameter has been allocated.
 * \return an async future.
 */
CTANKER_EXPORT tanker_future_t* tanker_destroy(tanker_t* tanker);

/*!
 * Connect to an event.
 * \param tanker A tanker tanker_t* instance.
 * \param event The event to connect.
 * \param data The data to pass to the callback.
 * \return an expected of NULL.
 * \warning Do not call this function after the session has been started.
 * \throws TANKER_ERROR_INVALID_ARGUMENT \p event does not exist
 */
CTANKER_EXPORT tanker_expected_t* tanker_event_connect(
    tanker_t* tanker,
    enum tanker_event event,
    tanker_event_callback_t cb,
    void* data);

/*!
 * Disconnect from an event.
 * \param tanker is not yet used.
 * \param event The event to disconnect.
 * \return an expected of NULL.
 */
CTANKER_EXPORT tanker_expected_t* tanker_event_disconnect(
    tanker_t* tanker, enum tanker_event event);

/*!
 * Sign up to Tanker.
 *
 * \param tanker a tanker tanker_t* instance.
 * \param identity the user identity.
 * \return a future of tanker_status
 * \throws TANKER_ERROR_INVALID_ARGUMENT \p indentity is NULL
 * \throws TANKER_ERROR_OTHER could not connect to the Tanker server
 * or the server returned an error
 * \throws TANKER_ERROR_OTHER could not open the local storage
 */
CTANKER_EXPORT tanker_future_t* tanker_start(tanker_t* tanker,
                                             char const* identity);

/*!
 * Register a verification method associated with an identity.
 *
 * \param tanker a tanker tanker_t* instance.
 * \param verification the verification methods to set up for the
 * user, must not be NULL.
 * \return a future of NULL
 * \throws TANKER_ERROR_INVALID_VERIFICATION_KEY unlock key is incorrect
 * \throws TANKER_ERROR_INVALID_VERIFICATION_CODE verification code is incorrect
 * \throws TANKER_ERROR_INVALID_UNLOCK_PASSWORD passphrase is incorrect
 * \throws TANKER_ERROR_OTHER could not connect to the Tanker server
 * or the server returned an error
 * \throws TANKER_ERROR_OTHER could not open the local storage
 */
CTANKER_EXPORT tanker_future_t* tanker_register_identity(
    tanker_t* tanker, tanker_verification_t const* verification);

/*!
 * Verify an identity with provided verification.
 *
 * \param tanker a tanker tanker_t* instance.
 * \param verification the verification methods to set up for the
 * user. Must not be NULL.
 * \return a future of NULL
 * \throws TANKER_ERROR_INVALID_VERIFICATION_KEY unlock key is incorrect
 * \throws TANKER_ERROR_INVALID_VERIFICATION_CODE verification code is incorrect
 * \throws TANKER_ERROR_INVALID_UNLOCK_PASSWORD passphrase is incorrect
 * \throws TANKER_ERROR_OTHER could not connect to the Tanker server
 * or the server returned an error
 * \throws TANKER_ERROR_OTHER could not open the local storage
 */
CTANKER_EXPORT tanker_future_t* tanker_verify_identity(
    tanker_t* tanker, tanker_verification_t const* verification);

/*!
 * Close a tanker session.
 * \param tanker A tanker tanker_t* instance.
 * \pre tanker must be allocated with tanker_create().
 * \pre tanker must be opened with tanker_open().
 */
CTANKER_EXPORT tanker_future_t* tanker_stop(tanker_t* tanker);

/*!
 * The current Tanker status.
 * \param tanker A tanker tanker_t* instance.
 * \pre tanker must be allocated with tanker_create().
 * \return the current Tanker status.
 */
CTANKER_EXPORT enum tanker_status tanker_status(tanker_t* tanker);

/*!
 * Get the current device id.
 * \param tanker A tanker_t* instance.
 * \pre tanker_status == TANKER_STATUS_READY
 * \return a future of char* that must be freed with tanker_free_buffer.
 */
CTANKER_EXPORT tanker_future_t* tanker_device_id(tanker_t* tanker);

/*!
 * Get the list of the user's devices.
 * \param tanker A tanker_t* instance.
 * \pre tanker_status == TANKER_STATUS_READY
 * \return a future of tanker_device_list_t* that must be freed with
 * tanker_free_device_list.
 */
CTANKER_EXPORT tanker_future_t* tanker_get_device_list(tanker_t* tanker);

/*!
 * Generate an verificationKey that can be used to accept a device
 * \param session A tanker tanker_t* instance
 * \pre tanker_status == TANKER_STATUS_READY
 * \return a future of char* that must be freed with tanker_free_buffer
 * \throws TANKER_ERROR_OTHER could not connect to the Tanker server or the
 * server returned an error
 */
CTANKER_EXPORT tanker_future_t* tanker_generate_verification_key(
    tanker_t* session);

/*!
 * Registers, or updates, the user's unlock claims,
 * creates an unlock key if necessary
 * \param session a tanker tanker_t* instance
 * \param verification a instance of tanker_verification_t
 * \pre tanker_status == TANKER_STATUS_READY
 * \return a future to void
 */
CTANKER_EXPORT tanker_future_t* tanker_set_verification_method(
    tanker_t* session, tanker_verification_t const* verification);

/*!
 * Return all registered verification methods for the current user.
 * \param session A tanker tanker_t* instance.
 * \pre tanker_status == TANKER_STATUS_READY
 * \return a tanker_verification_method_list_t*
 */
CTANKER_EXPORT tanker_future_t* tanker_get_verification_methods(
    tanker_t* session);

/*!
 * Get the encrypted size from the clear size.
 * Must be called before encrypt to allocate the encrypted buffer.
 */
CTANKER_EXPORT uint64_t tanker_encrypted_size(uint64_t clear_size);

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
CTANKER_EXPORT tanker_expected_t* tanker_decrypted_size(
    uint8_t const* encrypted_data, uint64_t encrypted_size);

/*!
 * Get the resource id from an encrypted data.
 * \return an already ready future of a char* that must be freed with
 * tanker_free_buffer.
 */
CTANKER_EXPORT tanker_expected_t* tanker_get_resource_id(
    uint8_t const* encrypted_data, uint64_t encrypted_size);

/*!
 * Encrypt data.
 * \param tanker A tanker tanker_t* instance.
 * \pre tanker_status == TANKER_STATUS_READY
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
CTANKER_EXPORT tanker_future_t* tanker_encrypt(
    tanker_t* tanker,
    uint8_t* encrypted_data,
    uint8_t const* data,
    uint64_t data_size,
    tanker_encrypt_options_t const* options);

/*!
 * Decrypt an encrypted data.
 *
 * \param session A tanker tanker_t* instance.
 * \pre tanker_status == TANKER_STATUS_READY
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
CTANKER_EXPORT tanker_future_t* tanker_decrypt(tanker_t* session,
                                               uint8_t* decrypted_data,
                                               uint8_t const* data,
                                               uint64_t data_size);

/*!
 * Share a symetric key of an encrypted data with other users.
 *
 * \param session A tanker tanker_t* instance.
 * \pre tanker_status == TANKER_STATUS_READY
 * \param recipient_public_identities Array containing the recipients' public
 * identities.
 * \param nb_recipient_public_identities The number of recipients in
 * recipient_public_identities.
 * \param recipient_gids Array of strings describing the recipient groups.
 * \param nb_recipient_gids The number of groups in recipient_gids.
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
CTANKER_EXPORT tanker_future_t* tanker_share(
    tanker_t* session,
    char const* const* recipient_public_identities,
    uint64_t nb_recipient_public_identities,
    char const* const* recipient_gids,
    uint64_t nb_recipient_gids,
    char const* const* resource_ids,
    uint64_t nb_resource_ids);

/*!
 * Attach a provisional identity to the current user
 *
 * \param session A tanker tanker_t* instance.
 * \pre tanker_status == TANKER_STATUS_READY
 * \param provisional_identity provisional identity you want to claim.
 *
 * \return A future of tanker_attach_result_t*.
 * \throws TANKER_ERROR_OTHER could not connect to the Tanker server or
 * the server returned an error
 */
CTANKER_EXPORT tanker_future_t* tanker_attach_provisional_identity(
    tanker_t* session, char const* provisional_identity);

/*!
 * Verify a provisional identity for the current user
 *
 * \param session A tanker tanker_t* instance.
 * \pre tanker_status == TANKER_STATUS_READY
 * \param verification the verification used to verify this provisional
 * identity.
 *
 * \return An empty future.
 * \throws TANKER_ERROR_OTHER could not connect to the Tanker server or
 * the server returned an error
 */
CTANKER_EXPORT tanker_future_t* tanker_verify_provisional_identity(
    tanker_t* session, tanker_verification_t const* verification);

/*!
 * Revoke a device by device id.
 *
 * \param session A tanker tanker_t* instance.
 * \pre tanker_status == TANKER_STATUS_READY
 * \param device_id the device identifier as returned by tanker_device_id().
 *
 * \return An empty future.
 * \throws TANKER_DEVICE_NOT_FOUND The device_id in parameter does not
 * corresponds to a valid device
 * \throws TANKER_INVALID_ARGUMENT The device_id in parameter correspond to
 * another user's device.
 */
CTANKER_EXPORT tanker_future_t* tanker_revoke_device(tanker_t* session,
                                                     char const* device_id);

CTANKER_EXPORT void tanker_free_buffer(void const* buffer);

CTANKER_EXPORT void tanker_free_device_list(tanker_device_list_t* list);

CTANKER_EXPORT void tanker_free_verification_method_list(
    tanker_verification_method_list_t* list);

CTANKER_EXPORT void tanker_free_attach_result(tanker_attach_result_t* result);

/*!
 * Hash a password before sending it to the application server where it will
 * be hashed again.
 *
 * If you decide to synchronize the Tanker passphrase with the user password,
 * you will need to hash it client-side (in addition to hashing it server-side,
 * as explained in the "Good practices" section of the documentation). This
 * function allows you to do that hashing.
 *
 * \warning This is not a password hash function, it is only used to
 * solve the specific problem of passphrase synchronization described above, a
 * proper password hash function is still needed server-side. Please read the
 * documentation for more detail.
 *
 * \param password the password to prehash
 *
 * \return an expected of the prehashed password which must be freed with
 * tanker_free_buffer
 *
 * \throws TANKER_ERROR_INVALID_ARGUMENT \p password is null or empty
 */
CTANKER_EXPORT tanker_expected_t* tanker_prehash_password(char const* password);

#ifdef __cplusplus
}
#endif

#endif
