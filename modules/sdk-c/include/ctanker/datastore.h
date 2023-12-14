#ifndef CTANKER_SDK_TANKER_DATASTORE_H
#define CTANKER_SDK_TANKER_DATASTORE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum tanker_datastore_error_code
{
  TANKER_DATASTORE_ERROR_INVALID_DATABASE_VERSION = 1,
  TANKER_DATASTORE_ERROR_RECORD_NOT_FOUND,
  TANKER_DATASTORE_ERROR_DATABASE_ERROR,
  TANKER_DATASTORE_ERROR_DATABASE_LOCKED,
  TANKER_DATASTORE_ERROR_DATABASE_CORRUPT,
  TANKER_DATASTORE_ERROR_DATABASE_TOO_RECENT,
  TANKER_DATASTORE_ERROR_CONSTRAINT_FAILED,

  TANKER_DATASTORE_ERROR_LAST,
};

enum tanker_datastore_onconflict
{
  TANKER_DATASTORE_ONCONFLICT_FAIL,
  TANKER_DATASTORE_ONCONFLICT_IGNORE,
  TANKER_DATASTORE_ONCONFLICT_REPLACE,

  TANKER_DATASTORE_ONCONFLICT_LAST,
};

#define TANKER_DATASTORE_ALLOCATION_NONE ((uint32_t)-1)

typedef void tanker_datastore_t;
typedef void tanker_datastore_error_handle_t;
typedef void tanker_datastore_device_get_result_handle_t;
typedef void tanker_datastore_cache_get_result_handle_t;

typedef void (*tanker_datastore_open_t)(tanker_datastore_error_handle_t* h,
                                        tanker_datastore_t** db,
                                        char const* data_path,
                                        char const* cache_path);
typedef void (*tanker_datastore_close_t)(tanker_datastore_t* db);

typedef void (*tanker_datastore_device_nuke_t)(tanker_datastore_t* datastore, tanker_datastore_error_handle_t* h);

typedef void (*tanker_datastore_put_serialized_device_t)(tanker_datastore_t* datastore,
                                                         tanker_datastore_error_handle_t* h,
                                                         uint8_t const* device,
                                                         uint32_t device_size);
typedef void (*tanker_datastore_find_serialized_device_t)(tanker_datastore_t* datastore,
                                                          tanker_datastore_device_get_result_handle_t* h);

typedef void (*tanker_datastore_put_cache_values_t)(tanker_datastore_t* datastore,
                                                    tanker_datastore_error_handle_t* h,
                                                    uint8_t const* const* keys,
                                                    uint32_t const* key_sizes,
                                                    uint8_t const* const* values,
                                                    uint32_t const* value_sizes,
                                                    uint32_t elem_count,
                                                    uint8_t onconflict);
typedef void (*tanker_datastore_find_cache_values_t)(tanker_datastore_t* datastore,
                                                     tanker_datastore_device_get_result_handle_t* h,
                                                     uint8_t const* const* keys,
                                                     uint32_t const* key_sizes,
                                                     uint32_t elem_count);

struct tanker_datastore_options
{
  tanker_datastore_open_t open;
  tanker_datastore_close_t close;

  tanker_datastore_device_nuke_t nuke;
  tanker_datastore_put_serialized_device_t put_serialized_device;
  tanker_datastore_find_serialized_device_t find_serialized_device;
  tanker_datastore_put_cache_values_t put_cache_values;
  tanker_datastore_find_cache_values_t find_cache_values;
};

typedef struct tanker_datastore_options tanker_datastore_options_t;

uint8_t* tanker_datastore_allocate_device_buffer(tanker_datastore_device_get_result_handle_t* result_handle,
                                                 uint32_t size);
void tanker_datastore_allocate_cache_buffer(tanker_datastore_cache_get_result_handle_t* result_handle,
                                            uint8_t** out_ptrs,
                                            uint32_t* sizes);
void tanker_datastore_report_error(tanker_datastore_error_handle_t* handle, uint8_t error_code, char const* message);

#ifdef __cplusplus
}
#endif

#endif
