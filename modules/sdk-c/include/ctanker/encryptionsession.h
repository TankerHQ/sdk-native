#ifndef CTANKER_SDK_TANKER_SESSION_H
#define CTANKER_SDK_TANKER_SESSION_H

#include <ctanker/async.h>
#include <ctanker/ctanker.h>
#include <ctanker/export.h>
#include <ctanker/stream.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct tanker_encryption_session tanker_encryption_session_t;

/*!
 * Create an encryption session that will allow doing multiple encryption
 * operations with a reduced number of keys.
 *
 * \param tanker A tanker_t* instance
 * \pre tanker_status == TANKER_STATUS_READY
 *
 * \return A tanker_future of a tanker_encryption_session_t.
 * \throws TANKER_ERROR_OTHER could not connect to the Tanker server or the
 * server returned an error
 */
CTANKER_EXPORT tanker_future_t* tanker_encryption_session_open(
    tanker_t* tanker, tanker_encrypt_options_t const* options);

/*!
 * Closes an encryption session instance
 * \param session an encryption session to be deleted
 * \return an async future
 */
CTANKER_EXPORT tanker_future_t* tanker_encryption_session_close(
    tanker_encryption_session_t* session);

/*!
 * Get the encrypted size from the clear size.
 * Must be called before encrypt to allocate the encrypted buffer.
 *
 * \remark There is no tanker_encryption_session_decrypted_size, use
 * tanker_decrypted_size for the inverse operation
 *
 * \param session an encryption session
 * \param clear_size the length of the clear data
 *
 */
CTANKER_EXPORT uint64_t tanker_encryption_session_encrypted_size(
    tanker_encryption_session_t* session, uint64_t clear_size);
/*!
 * Get the session's permanent resource id
 * \param session an encryption session
 * \return an already ready future of a char* that must be freed with
 * tanker_free_buffer.
 */
CTANKER_EXPORT tanker_expected_t* tanker_encryption_session_get_resource_id(
    tanker_encryption_session_t* session);

/*!
 * Encrypt data with the session, that can be decrypted with tanker_decrypt
 * \param session an encryption session
 * \param encrypted_data The container for the encrypted data.
 * \pre encrypted_data must be allocated with a call to
 *      tanker_encrypted_size() in order to get the size beforehand.
 * \param data The array of bytes to encrypt.
 * \pre data_size must be the size of the *data* parameter
 *
 * \return An empty future.
 */
CTANKER_EXPORT tanker_future_t* tanker_encryption_session_encrypt(
    tanker_encryption_session_t* session,
    uint8_t* encrypted_data,
    uint8_t const* data,
    uint64_t data_size);

/*!
 * Create an encryption stream for an encryption session
 *
 * Use the returned stream with the tanker_stream_* APIs. See
 * tanker_stream_encrypt for more details about this API.
 *
 * \param session An encryption session
 * \param cb The input callback
 * \param additional_data Additional data to give to cb
 *
 * \return A new stream encryptor, to be closed with tanker_stream_close
 */
CTANKER_EXPORT tanker_future_t* tanker_encryption_session_stream_encrypt(
    tanker_encryption_session_t* session,
    tanker_stream_input_source_t cb,
    void* additional_data);

#ifdef __cplusplus
}
#endif

#endif // CTANKER_SDK_TANKER_SESSION_H
