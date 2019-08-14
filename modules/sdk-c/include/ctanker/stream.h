#ifndef CTANKER_SDK_TANKER_STREAMS_H
#define CTANKER_SDK_TANKER_STREAMS_H

#include <stdint.h>

#include <ctanker/async.h>
#include <ctanker/base64.h>
#include <ctanker/ctanker.h>
#include <ctanker/export.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct tanker_stream tanker_stream_t;
typedef struct tanker_stream_read_operation tanker_stream_read_operation_t;

/*!
 * Function pointer called whenever a tanker streams need to read input.
 *
 * \param buffer Buffer with a capacity of *buffer_size* bytes
 * \param buffer_size The maximum number of bytes to read, always positive
 * \param operation The current read operation
 * \param additional_data additional data
 */
typedef void (*tanker_stream_input_source_t)(
    uint8_t* buffer,
    int64_t buffer_size,
    tanker_stream_read_operation_t* operation,
    void* additional_data);

/*!
 * Create an encryption stream
 *
 * \param tanker A tanker_t* instance
 * \param cb The input callback
 * \param additional_data Additional data to give to cb
 * \param options The encryption options
 *
 * \pre tanker_status == TANKER_STATUS_READY
 *
 * \return A new stream encryptor
 */
CTANKER_EXPORT tanker_future_t* tanker_stream_encrypt(
    tanker_t* tanker,
    tanker_stream_input_source_t cb,
    void* additional_data,
    tanker_encrypt_options_t const* options);

/*!
 * Create a decryption stream
 *
 * \param tanker A tanker_t* instance
 * \param cb The input callback
 * \param additional_data Additional data to give to cb
 *
 * \pre tanker_status == TANKER_STATUS_READY
 * \return A new stream encryptor
 */
CTANKER_EXPORT tanker_future_t* tanker_stream_decrypt(
    tanker_t* tanker, tanker_stream_input_source_t cb, void* additional_data);

/*!
 * Finish a read operation
 *
 * \param op The operation to finish
 * \param nb_read The number of bytes read during the operation, or -1 if an
 * error occurred.
 */
CTANKER_EXPORT void tanker_stream_read_operation_finish(
    tanker_stream_read_operation_t* op, int64_t nb_read);

/*!
 * Read input from a stream
 *
 * \param stream A tanker_stream_t* instance
 * \param buffer The output buffer
 * \param buffer_size The maximum number of bytes to read
 *
 * \pre stream was returned by tanker_stream_encrypt or tanker_stream_decrypt
 * \pre buffer must be capable to hold *buffer_size* bytes
 * \pre buffer_size must be positive
 *
 * Additionally, passing a buffer_size of 0 will either:
 * 1. Return 0 immediately when there is still buffered output
 * 2. Process input and buffer output, and then return 0
 *
 * This avoids waiting for the user's buffer to perform a read
 *
 * \return The number of bytes read
 */
CTANKER_EXPORT tanker_future_t* tanker_stream_read(tanker_stream_t* stream,
                                                   uint8_t* buffer,
                                                   int64_t buffer_size);

/*!
 * Get the resource id from a stream
 *
 * \param stream the stream
 * \return the resource id
 */
CTANKER_EXPORT tanker_expected_t* tanker_stream_get_resource_id(
    tanker_stream_t* stream);

/*!
 * Close a stream
 *
 * \param stream A tanker_stream_t* instance
 *
 * \pre stream was returned by tanker_stream_encrypt or tanker_stream_decrypt
 * \post stream must not be reused
 *
 * \return An empty future
 */
CTANKER_EXPORT tanker_future_t* tanker_stream_close(tanker_stream_t* stream);

#ifdef __cplusplus
}
#endif

#endif // CTANKER_SDK_TANKER_STREAMS_H
