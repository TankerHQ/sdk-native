#ifndef TANKER_FILEKIT_C_H
#define TANKER_FILEKIT_C_H

#include <ctanker/async.h>
#include <ctanker/export.h>
#include <ctanker/stream.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct tanker_upload_options tanker_upload_options_t;

typedef struct tanker_metadata tanker_metadata_t;
typedef struct tanker_download_result tanker_download_result_t;
typedef struct tanker_download_stream_result tanker_download_stream_result_t;

struct tanker_metadata
{
  uint8_t version;
  char const* mime;
  char const* name;
  uint64_t last_modified;
};

#define TANKER_METADATA_INIT \
  {                          \
    1, NULL, NULL, 0         \
  }

struct tanker_upload_options
{
  uint8_t version;
  char const* const* recipient_public_identities;
  uint32_t nb_recipient_public_identities;
  char const* const* recipient_gids;
  uint32_t nb_recipient_gids;
};

#define TANKER_UPLOAD_OPTIONS_INIT \
  {                                \
    1, NULL, 0, NULL, 0            \
  }

struct tanker_download_result
{
  tanker_metadata_t* metadata;
  uint8_t* data;
  uint64_t data_size;
};

struct tanker_download_stream_result
{
  tanker_stream_t* stream;
  tanker_metadata_t* metadata;
};

/*!
 * Destroy a tanker_download_result_t returned.
 * \param download_result the download_result struct to destroy.
 */
tanker_future_t* tanker_download_result_destroy(
    tanker_download_result_t* download_result);

/*!
 * Destroys a tanker_download_stream_result_t returned.
 * \param download_result the download_result struct to destroy.
 */
tanker_future_t* tanker_download_stream_result_destroy(
    tanker_download_stream_result_t* download_result);

/*!
 * Encrypt and Upload data to the storage.
 * \param data the data to encrypt and upload.
 * \param data_size the size of the data given.
 * \param metadata the metadata associated with the data, it will be encrypted
 * too.
 * \param options options to encrypt and share the data.
 * \return a tanker_future_t that contains the resource id of the uploaded data.
 */
CTANKER_EXPORT tanker_future_t* tanker_upload(tanker_t* tanker,
                                              uint8_t const* data,
                                              uint64_t data_size,
                                              tanker_metadata_t* metadata,
                                              tanker_upload_options_t* options);
/*!
 * Encrypt and Upload data to the storage using a stream.
 */
CTANKER_EXPORT tanker_future_t* tanker_upload_stream(
    tanker_t* tanker,
    tanker_stream_input_source_t source,
    uint64_t data_size,
    tanker_metadata_t* metadata,
    tanker_upload_options_t* options);

/*!
 * Download a resource from the storage.
 * \param resource_id the resource id of the file you want to download.
 * \return a tanker_download_result_t* that must be destroyed with
 * tanker_download_result_destroy().
 */
CTANKER_EXPORT tanker_future_t* tanker_download(tanker_t* tanker,
                                                char const* resource_id);

/*!
 * Download a resource from the storage using a stream.
 * \param resource_id the resource id of the file you want to download.
 * \return a tanker_download_stream_result_t* that must be destroyed with
 * tanker_download_stream_result_destroy().
 */
CTANKER_EXPORT tanker_future_t* tanker_download_stream(tanker_t* tanker,
                                                       char const* resource_id);

#ifdef __cplusplus
}
#endif

#endif
