#include <ctanker/network.h>

#include <Tanker/Errors/Exception.hpp>
#include <Tanker/Log/Log.hpp>
#include <ctanker/private/CNetwork.hpp>
#include <ctanker/private/Utils.hpp>

#include <tconcurrent/promise.hpp>

#ifdef _WIN32
#include <process.h>
#else
#include <unistd.h>
#endif

TLOG_CATEGORY(CTankerBackend);

using namespace Tanker::Network;

struct tanker_http_request_internal
{
  // This must be the first field for binary compatibility
  tanker_http_request_t request;
  tc::promise<HttpResponse> promise;
};

CTankerBackend::CTankerBackend(tanker_http_options_t const& options) : _options(options)
{
}

tc::cotask<HttpResponse> CTankerBackend::fetch(HttpRequest req)
{
  printf("@@@ PID=%d ctanker CTankerBackend::fetch reached\n", getpid());
  fflush(stdout);

  using namespace HttpHeader;

  tanker_http_request_internal request{};
  request.request.method = httpMethodToString(req.method);
  request.request.url = req.url.c_str();
  request.request.body = req.body.c_str();
  request.request.body_size = req.body.size();

  std::vector<tanker_http_header_t> c_headers;
  for (auto const& [name, value] : req.headers)
    c_headers.push_back({name.c_str(), value.c_str()});
  request.request.headers = c_headers.data();
  request.request.num_headers = c_headers.size();

  // [&] capture is fine because we await the end just below
  tanker_http_request_handle_t* requestHandle;
  auto const scope = request.promise.get_cancelation_token().make_scope_canceler([&] {
    tc::dispatch_on_thread_context([&] { _options.cancel_request(&request.request, requestHandle, _options.data); });
  });
  printf("@@@ PID=%d ctanker CTankerBackend::fetch about to dispatch_on_thread_context\n", getpid());
  fflush(stdout);
  requestHandle = tc::dispatch_on_thread_context([&] {
    printf("@@@ PID=%d ctanker CTankerBackend::fetch inside dispatch_on_thread_context, calling ruby\n", getpid());
    fflush(stdout);
    return _options.send_request(&request.request, _options.data);
  });
  printf("@@@ PID=%d ctanker CTankerBackend::fetch received promise, waiting on Ruby response\n", getpid());
  fflush(stdout);
  TC_RETURN(TC_AWAIT(request.promise.get_future()));
}

void tanker_http_handle_response(tanker_http_request_t* pubRequest, tanker_http_response_t* cresponse)
{
  printf("@@@ PID=%d ctanker tanker_http_handle_response reached\n", getpid());
  fflush(stdout);

  auto const crequest = reinterpret_cast<tanker_http_request_internal*>(pubRequest);

  if (cresponse->error_msg)
  {
    crequest->promise.set_exception(std::make_exception_ptr(
        Tanker::Errors::Exception(make_error_code(Tanker::Errors::Errc::NetworkError), cresponse->error_msg)));
    return;
  }

  if (cresponse->body_size < 0)
  {
    crequest->promise.set_exception(std::make_exception_ptr(
        Tanker::Errors::Exception(make_error_code(Tanker::Errors::Errc::InternalError),
                                  fmt::format("invalid response body size: {}", cresponse->body_size))));
    return;
  }

  HttpResponse response;
  response.statusCode = cresponse->status_code;
  for (int32_t i = 0; i < cresponse->num_headers; i++)
    response.headers.append(cresponse->headers[i].name, cresponse->headers[i].value);
  response.body = std::string(cresponse->body, cresponse->body_size);
  printf("@@@ PID=%d ctanker tanker_http_handle_response set promise value\n", getpid());
  crequest->promise.set_value(std::move(response));
}
