#ifndef CTANKER_SDK_TANKER_TANKER_H
#define CTANKER_SDK_TANKER_TANKER_H

#include <ctanker/async.h>
#include <ctanker/datastore.h>
#include <ctanker/export.h>
#include <ctanker/network.h>

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

  TANKER_EVENT_LAST,
};

enum tanker_verification_method_type
{
  TANKER_VERIFICATION_METHOD_EMAIL = 0x1,
  TANKER_VERIFICATION_METHOD_PASSPHRASE,
  TANKER_VERIFICATION_METHOD_VERIFICATION_KEY,
  TANKER_VERIFICATION_METHOD_OIDC_ID_TOKEN,
  TANKER_VERIFICATION_METHOD_PHONE_NUMBER,
  TANKER_VERIFICATION_METHOD_PREVERIFIED_EMAIL,
  TANKER_VERIFICATION_METHOD_PREVERIFIED_PHONE_NUMBER,
  TANKER_VERIFICATION_METHOD_E2E_PASSPHRASE,
  TANKER_VERIFICATION_METHOD_PREVERIFIED_OIDC,
  TANKER_VERIFICATION_METHOD_OIDC_AUTHORIZATION_CODE,

  TANKER_VERIFICATION_METHOD_LAST,
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
typedef struct tanker_phone_number_verification tanker_phone_number_verification_t;
typedef struct tanker_preverified_oidc_verification tanker_preverified_oidc_verification_t;
typedef struct tanker_oidc_authorization_code_verification tanker_oidc_authorization_code_verification_t;
typedef struct tanker_verification tanker_verification_t;
typedef struct tanker_verification_list tanker_verification_list_t;
typedef struct tanker_verification_method tanker_verification_method_t;
typedef struct tanker_verification_options tanker_verification_options_t;
typedef struct tanker_encrypt_options tanker_encrypt_options_t;
typedef struct tanker_sharing_options tanker_sharing_options_t;
typedef struct tanker_log_record tanker_log_record_t;
typedef struct tanker_verification_method_list tanker_verification_method_list_t;
typedef struct tanker_attach_result tanker_attach_result_t;

/*!
 * \brief The list of a user verification methods
 */
struct tanker_verification_method_list
{
  tanker_verification_method_t* methods;
  uint32_t count;
};

/*!
 * \brief The list of a user verifications
 */
struct tanker_verification_list
{
  uint8_t version;
  tanker_verification_t* verifications;
  uint32_t count;
};

#define TANKER_VERIFICATION_LIST_INIT \
  {                                   \
    1, NULL, 0                        \
  }

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
  char const* app_id;          /*!< Must not be NULL. */
  char const* url;             /*!< Must not be NULL. */
  char const* persistent_path; /*!< Must not be NULL. */
  char const* cache_path;      /*!< Must not be NULL. */
  char const* sdk_type;        /*!< Must not be NULL. */
  char const* sdk_version;     /*!< Must not be NULL. */

  tanker_http_options_t http_options;
  tanker_datastore_options_t datastore_options;
};

#define TANKER_OPTIONS_INIT                                    \
  {                                                            \
    4, NULL, NULL, NULL, NULL, NULL, NULL, {NULL, NULL, NULL}, \
    {                                                          \
      NULL, NULL, NULL, NULL, NULL, NULL, NULL                 \
    }                                                          \
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

struct tanker_phone_number_verification
{
  uint8_t version;
  char const* phone_number;
  char const* verification_code;
};

#define TANKER_PHONE_NUMBER_VERIFICATION_INIT \
  {                                           \
    1, NULL, NULL                             \
  }

struct tanker_preverified_oidc_verification
{
  uint8_t version;
  char const* subject;
  char const* provider_id;
};

#define TANKER_PREVERIFIED_OIDC_VERIFICATION_INIT \
  {                                               \
    1, NULL, NULL                                 \
  }

struct tanker_oidc_authorization_code_verification
{
  uint8_t version;
  char const* provider_id;
  char const* authorization_code;
  char const* state;
};

#define TANKER_OIDC_AUTHORIZATION_CODE_INIT       \
  {                                               \
    1, NULL, NULL, NULL                           \
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
  char const* e2e_passphrase;
  char const* oidc_id_token;
  tanker_phone_number_verification_t phone_number_verification;
  char const* preverified_email;
  char const* preverified_phone_number;
  tanker_preverified_oidc_verification_t preverified_oidc_verification;
  tanker_oidc_authorization_code_verification_t oidc_authorization_code_verification;
};

#define TANKER_VERIFICATION_INIT                                                                               \
  {                                                                                                            \
    8, 0, NULL, TANKER_EMAIL_VERIFICATION_INIT, NULL, NULL, NULL, TANKER_PHONE_NUMBER_VERIFICATION_INIT, NULL, \
    NULL, TANKER_PREVERIFIED_OIDC_VERIFICATION_INIT, TANKER_OIDC_AUTHORIZATION_CODE_INIT                       \
  }

struct tanker_verification_method
{
  // This field is actually useless because we only return
  // tanker_verification_method_t, we never receive it as an argument.
  uint8_t version;
  // enum cannot be bound to java as they do not have a fixed size.
  // It takes a value from tanker_verification_method_type:
  uint8_t verification_method_type;
  // Fields of the verification method (may be NULL)
  char const* value1;
  char const* value2;
};

struct tanker_verification_options
{
  uint8_t version;
  bool with_session_token;
  bool allow_e2e_method_switch;
};

#define TANKER_VERIFICATION_OPTIONS_INIT \
  {                                      \
    2, false, false                      \
  }

struct tanker_encrypt_options
{
  uint8_t version;
  char const* const* share_with_users;
  uint32_t nb_users;
  char const* const* share_with_groups;
  uint32_t nb_groups;
  bool share_with_self;

  // if padding_step == 0 then automatic padding
  // else if padding_step == 1 then padding disabled
  // else pad to a multiple of padding_step
  uint32_t padding_step;
};

#define TANKER_ENCRYPT_OPTIONS_INIT \
  {                                 \
    4, NULL, 0, NULL, 0, true, 0    \
  }

struct tanker_sharing_options
{
  uint8_t version;
  char const* const* share_with_users;
  uint32_t nb_users;
  char const* const* share_with_groups;
  uint32_t nb_groups;
};

#define TANKER_SHARING_OPTIONS_INIT \
  {                                 \
    1, NULL, 0, NULL, 0             \
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
CTANKER_EXPORT tanker_expected_t* tanker_event_connect(tanker_t* tanker,
                                                       enum tanker_event event,
                                                       tanker_event_callback_t cb,
                                                       void* data);

/*!
 * Disconnect from an event.
 * \param tanker is not yet used.
 * \param event The event to disconnect.
 * \return an expected of NULL.
 */
CTANKER_EXPORT tanker_expected_t* tanker_event_disconnect(tanker_t* tanker, enum tanker_event event);

/*!
 * Sign up to Tanker.
 *
 * \param tanker a tanker tanker_t* instance.
 * \param identity the user identity.
 * \return a future of tanker_status
 * \throws TANKER_ERROR_INVALID_ARGUMENT \p identity is NULL
 * \throws TANKER_ERROR_OTHER could not connect to the Tanker server
 * or the server returned an error
 * \throws TANKER_ERROR_OTHER could not open the local storage
 */
CTANKER_EXPORT tanker_future_t* tanker_start(tanker_t* tanker, char const* identity);

/*!
 * Enrolls a user to Tanker. And assigns its pre-verified verification methods
 *
 * \param tanker a tanker tanker_t* instance.
 * \param identity the user identity.
 * \param verifications the pre-verified verification methods of the user
 * \return an expected of NULL
 * \throws TANKER_ERROR_INVALID_ARGUMENT \p identity is NULL
 * \throws TANKER_ERROR_INVALID_ARGUMENT \p verifications is ill-formed
 * \throws TANKER_ERROR_NETWORK_ERROR could not connect to the Tanker server
 * \throws TANKER_ERROR_CONFLICT the identity is already registered or enrolled
 */
CTANKER_EXPORT tanker_expected_t* tanker_enroll_user(tanker_t* tanker,
                                                     char const* identity,
                                                     tanker_verification_list_t const* verifications);

/*!
 * Register a verification method associated with an identity.
 *
 * \param tanker a tanker tanker_t* instance.
 * \param verification the verification methods to set up for the
 * user, must not be NULL.
 * \return a future of NULL if with_session_token is false, otherwise a
 * session token string that must be freed with tanker_free_buffer.
 * \throws TANKER_ERROR_INVALID_VERIFICATION_KEY unlock key is incorrect
 * \throws TANKER_ERROR_INVALID_VERIFICATION_CODE verification code is incorrect
 * \throws TANKER_ERROR_INVALID_UNLOCK_PASSWORD passphrase is incorrect
 * \throws TANKER_ERROR_OTHER could not connect to the Tanker server
 * or the server returned an error
 * \throws TANKER_ERROR_OTHER could not open the local storage
 */
CTANKER_EXPORT tanker_future_t* tanker_register_identity(tanker_t* tanker,
                                                         tanker_verification_t const* verification,
                                                         tanker_verification_options_t const* cverif_opts);

/*!
 * Verify an identity with provided verification.
 *
 * \param tanker a tanker tanker_t* instance.
 * \param verification the verification methods to set up for the
 * user. Must not be NULL.
 * \return a future of NULL if with_session_token is false, otherwise a
 * session token string that must be freed with tanker_free_buffer.
 * \throws TANKER_ERROR_INVALID_VERIFICATION_KEY unlock key is incorrect
 * \throws TANKER_ERROR_INVALID_VERIFICATION_CODE verification code is incorrect
 * \throws TANKER_ERROR_INVALID_UNLOCK_PASSWORD passphrase is incorrect
 * \throws TANKER_ERROR_OTHER could not connect to the Tanker server
 * or the server returned an error
 * \throws TANKER_ERROR_OTHER could not open the local storage
 */
CTANKER_EXPORT tanker_future_t* tanker_verify_identity(tanker_t* tanker,
                                                       tanker_verification_t const* verification,
                                                       tanker_verification_options_t const* cverif_opts);

/*!
 * Close a tanker session.
 * \param tanker A tanker tanker_t* instance.
 * \pre tanker must be allocated with tanker_create().
 * \pre tanker must be opened with tanker_open().
 */
CTANKER_EXPORT tanker_future_t* tanker_stop(tanker_t* tanker);

/*!
 * Create a nonce to use in the oidc authorization code flow
 * \param tanker A tanker tanker_t* instance.
 * \pre tanker must be allocated with tanker_create().
 */
CTANKER_EXPORT tanker_future_t* tanker_create_oidc_nonce(tanker_t* tanker);

/*!
 * Set the nonce to use while testing oidc verification
 */
CTANKER_EXPORT tanker_future_t* tanker_set_oidc_test_nonce(tanker_t* tanker, char const* nonce);

/*!
 * The current Tanker status.
 * \param tanker A tanker tanker_t* instance.
 * \pre tanker must be allocated with tanker_create().
 * \return the current Tanker status.
 */
CTANKER_EXPORT enum tanker_status tanker_status(tanker_t* tanker);

/*!
 * Generate an verificationKey that can be used to accept a device
 * \param session A tanker tanker_t* instance
 * \pre tanker_status == TANKER_STATUS_READY
 * \return a future of char* that must be freed with tanker_free_buffer
 * \throws TANKER_ERROR_OTHER could not connect to the Tanker server or the
 * server returned an error
 */
CTANKER_EXPORT tanker_future_t* tanker_generate_verification_key(tanker_t* session);

/*!
 * Registers, or updates, the user's unlock claims,
 * creates an unlock key if necessary
 * \param session a tanker tanker_t* instance
 * \param verification a instance of tanker_verification_t
 * \pre tanker_status == TANKER_STATUS_READY
 * \return a future of NULL if with_session_token is false, otherwise a
 * session token string that must be freed with tanker_free_buffer.
 */
CTANKER_EXPORT tanker_future_t* tanker_set_verification_method(tanker_t* session,
                                                               tanker_verification_t const* verification,
                                                               tanker_verification_options_t const* cverif_opts);

/*!
 * Return all registered verification methods for the current user.
 * \param session A tanker tanker_t* instance.
 * \pre tanker_status == TANKER_STATUS_READY
 * \return a tanker_verification_method_list_t*
 */
CTANKER_EXPORT tanker_future_t* tanker_get_verification_methods(tanker_t* session);

/*!
 * Get the encrypted size from the clear size.
 * Must be called before encrypt to allocate the encrypted buffer.
 * \param clear_size The length of the clear data.
 * \param padding_step The same padding step that should be provided in the
 * encryption options.
 */
CTANKER_EXPORT uint64_t tanker_encrypted_size(uint64_t clear_size, uint32_t padding_step);

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
CTANKER_EXPORT tanker_expected_t* tanker_decrypted_size(uint8_t const* encrypted_data, uint64_t encrypted_size);

/*!
 * Get the resource id from an encrypted data.
 * \return an already ready future of a char* that must be freed with
 * tanker_free_buffer.
 */
CTANKER_EXPORT tanker_expected_t* tanker_get_resource_id(uint8_t const* encrypted_data, uint64_t encrypted_size);

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
CTANKER_EXPORT tanker_future_t* tanker_encrypt(tanker_t* tanker,
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
 * \return A future that contains the size of the clear data cast to a void*.
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
 * \param resource_ids Array of string describing the resources.
 * \param nb_resource_ids The number of resources in resource_ids.
 * \param options The users and groups to share with.
 *
 * \return An empty future.
 * \throws TANKER_ERROR_RECIPIENT_NOT_FOUND One of the recipients was not found,
 * no action was done
 * \throws TANKER_ERROR_RESOURCE_KEY_NOT_FOUND One of the
 * resource keys was not found, no action was done
 * \throws TANKER_ERROR_OTHER could not connect to the Tanker server or the
 * server returned an error
 */
CTANKER_EXPORT tanker_future_t* tanker_share(tanker_t* session,
                                             char const* const* resource_ids,
                                             uint64_t nb_resource_ids,
                                             tanker_sharing_options_t const* options);

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
CTANKER_EXPORT tanker_future_t* tanker_attach_provisional_identity(tanker_t* session, char const* provisional_identity);

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
CTANKER_EXPORT tanker_future_t* tanker_verify_provisional_identity(tanker_t* session,
                                                                   tanker_verification_t const* verification);

/*!
 * Authenticates against a trusted identity provider.
 * \pre The identity provider must be a OIDC provider configured on the trustchain.
 *
 * \warning This API is exposed for testing purposes only.
 *
 * \param session A tanker tanker_t* instance.
 * \pre tanker_status != TANKER_STATUS_STOPPED
 * \param provider_id oidc provider id of the trusted identity provider (as returned by the app managment API)
 * \param cookie a cookie-list added to the authorization HTTP request (see https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cookie)
 *
 * \return A future of tanker_oidc_authorization_code_verification*
 *
 * \throws TANKER_ERROR_OTHER an error occured during OIDC authorization
 */
CTANKER_EXPORT tanker_future_t* tanker_authenticate_with_idp(tanker_t* session, char const* provider_id, char const* cookie);

CTANKER_EXPORT void tanker_free_buffer(void const* buffer);

CTANKER_EXPORT void tanker_free_verification_method_list(tanker_verification_method_list_t* list);

CTANKER_EXPORT void tanker_free_attach_result(tanker_attach_result_t* result);

CTANKER_EXPORT void tanker_free_authenticate_with_idp_result(tanker_oidc_authorization_code_verification_t* result);

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
