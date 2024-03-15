#include <ctanker/network.h>

#include <Tanker/Errors/Exception.hpp>
#include <Tanker/Log/Log.hpp>
#include <ctanker/private/CNetwork.hpp>
#include <ctanker/private/Utils.hpp>

#include <tconcurrent/promise.hpp>

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
  using namespace HttpHeader;

  tanker_http_request_internal request{};
  request.request.method = httpMethodToString(req.method);
  request.request.url = req.url.c_str();
  request.request.instance_id = req.headers.get(TANKER_INSTANCE_ID)->c_str();
  if (auto authorization = req.headers.get(AUTHORIZATION))
    request.request.authorization = authorization->c_str();
  request.request.body = req.body.c_str();
  request.request.body_size = req.body.size();

  // [&] capture is fine because we await the end just below
  tanker_http_request_handle_t* requestHandle;
  auto const scope = request.promise.get_cancelation_token().make_scope_canceler([&] {
    tc::dispatch_on_thread_context([&] { _options.cancel_request(&request.request, requestHandle, _options.data); });
  });
  requestHandle =
      tc::dispatch_on_thread_context([&] { return _options.send_request(&request.request, _options.data); });
  TC_RETURN(TC_AWAIT(request.promise.get_future()));
}

void tanker_http_handle_response(tanker_http_request_t* pubRequest, tanker_http_response_t* cresponse)
{
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
  response.contentType = cresponse->content_type ? cresponse->content_type : std::string{};
  response.body = std::string(cresponse->body, cresponse->body_size);
  crequest->promise.set_value(std::move(response));
}
