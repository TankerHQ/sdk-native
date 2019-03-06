#ifndef CTANKER_SDK_TANKER_CHUNK_ENCRYPTOR_H
#define CTANKER_SDK_TANKER_CHUNK_ENCRYPTOR_H

#include <stdint.h>

#include <ctanker/async.h>
#include <ctanker/base64.h>
#include <ctanker/ctanker.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct tanker_chunk_encryptor tanker_chunk_encryptor_t;

/*!
 * Create an empty chunk encryptor.
 * \param session A tanker tanker_t* instance.
 * \pre tanker_status == TANKER_STATUS_OPEN
 * \return an async future of a tanker_chunk_encryptor_t.
 */
tanker_future_t* tanker_make_chunk_encryptor(tanker_t* session);

/*!
 * Create a chunk encryptor from an existing seal.
 * \param session A tanker tanker_t* instance.
 * \pre tanker_status == TANKER_STATUS_OPEN
 * \param data an encrypted seal.
 * \pre data must be a valid encrypted seal.
 * \pre data_size must be the size of the data parameter.
 * \return an async future of a tanker_chunk_encryptor_t.
 * \throws TANKER_ERROR_VERSION_NOT_SUPPORTED \p version of the seal is too
 * recent.
 * \throws TANKER_ERROR_DECRYPT_FAILED \p cannot decrypt seal data.
 */
tanker_future_t* tanker_make_chunk_encryptor_from_seal(
    tanker_t* session,
    uint8_t const* data,
    uint64_t data_size,
    tanker_decrypt_options_t const* options);

/*!
 * Get the seal size from the chunk encryptor.
 * Must be called before chunk_encryptor_seal to allocate the encrypted seal.
 */
uint64_t tanker_chunk_encryptor_seal_size(
    tanker_chunk_encryptor_t* chunk_encryptor);

/*!
 * Seal the chunk encryptor.
 * \pre chunk_encryptor must be allocated with tanker_make_chunk_encryptor().
 * \param encrypted_seal The container for the encrypted seal.
 * \pre encrypted_seal must be allocated with a call to
 *      tanker_chunk_encryptor_seal_size() in order to get the size beforehand.
 * \return an empty future.
 */
tanker_future_t* tanker_chunk_encryptor_seal(
    tanker_chunk_encryptor_t* chunk_encryptor,
    uint8_t* encrypted_seal,
    tanker_encrypt_options_t const* options);

/*!
 * Get the number of chunks in the chunk encryptor.
 */
uint64_t tanker_chunk_encryptor_chunk_count(
    tanker_chunk_encryptor_t* chunk_encryptor);

/*!
 * Append data into the chunk encryptor.
 * \pre chunk_encryptor must be allocated with tanker_make_chunk_encryptor().
 * \param encrypted_data The container for the encrypted data.
 * \pre encrypted_data must be allocated with a call to
 *      tanker_chunk_encryptor_encrypted_size() in order to get the size
 *      beforehand.
 * \param data The array of bytes to encrypt.
 * \pre data_size must be the size of the *data* parameter
 * \return an empty future.
 */
tanker_future_t* tanker_chunk_encryptor_encrypt_append(
    tanker_chunk_encryptor_t* chunk_encryptor,
    uint8_t* encrypted_data,
    uint8_t const* data,
    uint64_t data_size);

/*!
 * Encrypt data into chunk encryptor at index.
 * If the index is bigger than the size empty chunks are appended in between.
 * \pre chunk_encryptor must be allocated with tanker_make_chunk_encryptor().
 * \param encrypted_data The container for the encrypted data.
 * \pre encrypted_data must be allocated with a call to
 *      tanker_chunk_encryptor_encrypted_size() in order to get the size
 *      beforehand.
 * \param data The array of bytes to encrypt.
 * \param index the index of the element to encrypt at.
 * \pre data_size must be the size of the *data* parameter
 * \return an empty future.
 */
tanker_future_t* tanker_chunk_encryptor_encrypt_at(
    tanker_chunk_encryptor_t* chunk_encryptor,
    uint8_t* encrypted_data,
    uint8_t const* data,
    uint64_t data_size,
    uint64_t index);

/*!
 * Decrypt the data from the chunk encryptor at the given index.
 * \pre chunk_encryptor must be allocated with tanker_make_chunk_encryptor().
 * \param index the index of the element to decrypt.
 * \pre index must be whithin the range of the chunk_encryptor size()
 * \param decrypted_data The container for the decrypted data.
 * \pre decrypted_data must be allocated with a call to
 *      tanker_chunk_encryptor_decrypted_size() in order to get the size
 *      beforehand.
 * \param encrypted_data The array of bytes to decrypt.
 * \pre encrypted_data_size must be the size of the *encrypted_data* parameter
 * \return an empty future.
 * \throws TANKER_ERROR_CHUNK_INDEX_OUT_OF_RANGE \p index is superior to the
 * number of chunks.
 * \throws TANKER_ERROR_CHUNK_INVALID_ARGUMENT \p chunk at index is empty.
 */
tanker_future_t* tanker_chunk_encryptor_decrypt(
    tanker_chunk_encryptor_t* chunk_encryptor,
    uint8_t* decrypted_data,
    uint8_t const* encrypted_data,
    uint64_t encrypted_data_size,
    uint64_t index);

/*!
 * Get the encrypted size from the clear size.
 * Must be called before encrypt to allocate the encrypted buffer.
 */
uint64_t tanker_chunk_encryptor_encrypted_size(uint64_t clear_size);

/*!
 * Get the decrypted size.
 *
 * Must be called before decrypt to allocate the decrypted buffer.
 *
 * \return The size the decrypted data would take, cast to a void*, or an error
 * if the data is corrupted.
 * \throws TANKER_ERROR_DECRYPT_FAILED the buffer is corrupt or truncated
 */
tanker_expected_t* tanker_chunk_encryptor_decrypted_size(
    uint8_t const* encrypted_data, uint64_t encrypted_size);

/*!
 * Remove the chunks from the chunk encryptor at given indexes.
 * \pre chunk_encryptor must be allocated with tanker_make_chunk_encryptor().
 * \param indexes list of all the indexes to remove from the chunk_encryptor.
 * \pre all the indexes must be whithin the range of the chunk encryptor size().
 * \pre indexes_size must be the size of the *indexes* parameter.
 * \return an empty future.
 * \throws TANKER_ERROR_CHUNK_INDEX_OUT_OF_RANGE \p one or more of the indexes
 * are superior to the number of chunks.
 */
tanker_future_t* tanker_chunk_encryptor_remove(
    tanker_chunk_encryptor_t* chunk_encryptor,
    uint64_t const* indexes,
    uint64_t indexes_size);

/*!
 * Destroys the chunk encryptor.
 * \pre chunk_encryptor must be allocated with tanker_make_chunk_encryptor().
 * \return an already ready empty future.
 */
tanker_expected_t* tanker_chunk_encryptor_destroy(
    tanker_chunk_encryptor_t* chunk_encryptor);

#ifdef __cplusplus
}
#endif

#endif
