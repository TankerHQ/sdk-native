#ifndef CTANKER_SDK_TANKER_NETWORK_H
#define CTANKER_SDK_TANKER_NETWORK_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct tanker_http_request
{
  char const* method;
  char const* url;
  char const* instance_id;
  char const* authorization;
  char const* body;
  int32_t body_size;
};

struct tanker_http_response
{
  char const* error_msg;
  char const* content_type;
  char const* body;
  int64_t body_size;
  int32_t status_code;
};

typedef struct tanker_http_request tanker_http_request_t;
typedef struct tanker_http_response tanker_http_response_t;

// Opaque object that represents a request
typedef void tanker_http_request_handle_t;

typedef tanker_http_request_handle_t* (*tanker_http_send_request_t)(
    tanker_http_request_t* request, void* data);
typedef void (*tanker_http_cancel_request_t)(
    tanker_http_request_t* request,
    tanker_http_request_handle_t* request_handle,
    void* data);

void tanker_http_handle_response(tanker_http_request_t*,
                                 tanker_http_response_t*);

#ifdef __cplusplus
}
#endif

#endif
