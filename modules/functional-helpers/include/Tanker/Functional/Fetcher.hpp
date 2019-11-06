#pragma once

#include <boost/asio/strand.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/version.hpp>

namespace Tanker
{

namespace fetch
{
namespace beast = boost::beast;
namespace http = beast::http;
namespace net = boost::asio;
namespace ssl = net::ssl;
using tcp = boost::asio::ip::tcp;

template <typename BodyRequest = http::string_body>
using request = http::request<BodyRequest>;
template <typename BodyResponse = http::string_body>
using response = http::response<BodyResponse>;

namespace detail
{
template <typename AsyncStream>
struct composer_state
{
  std::string host;
  AsyncStream& stream;
  tcp::resolver resolver;
  request<>& req;
  beast::flat_buffer buffer;
  response<>& res;
  composer_state(std::string host,
                 AsyncStream& stream,
                 request<>& req,
                 response<>& res)
    : host(std::move(host)),
      stream(stream),
      resolver(stream.get_executor()),
      req(req),
      res(res)
  {
  }
};
}

template <typename AsyncStream, typename CompletionHandler>
auto async_get(AsyncStream& stream,
               std::string host,
               request<>& req,
               response<>& res,
               CompletionHandler&& handler) ->
    typename net::async_result<typename std::decay_t<CompletionHandler>,
                               void(beast::error_code, response<>)>::return_type
{
  using handler_type =
      typename net::async_completion<CompletionHandler,
                                     void(beast::error_code,
                                          response<>)>::completion_handler_type;
  using base_type =
      beast::stable_async_base<handler_type,
                               typename AsyncStream::executor_type>;

  struct composer : base_type
  {
    detail::composer_state<AsyncStream>& data;
    enum class status : int
    {
      starting,
      resolving,
      connecting,
      handshaking,
      sending,
      receiving,
      closing,
    } state = status::starting;

    composer(std::string host,
             AsyncStream& stream,
             request<>& req,
             response<>& res,
             handler_type& handler)
      : base_type(std::move(handler), stream.get_executor()),
        data(beast::allocate_stable<detail::composer_state<AsyncStream>>(
            *this, std::move(host), stream, req, res))
    {
      (*this)();
    }

    void operator()(beast::error_code ec = {}, std::size_t n = 0)
    {
      if (!ec)
      {
        switch (state)
        {
        case status::starting:
          state = status::resolving;
          data.resolver.async_resolve(data.host, "https", std::move(*this));
          return;
        case status::handshaking:
          state = status::sending;
          http::async_write(data.stream, data.req, std::move(*this));
          return;
        case status::sending:
          state = status::receiving;
          http::async_read(
              data.stream, data.buffer, data.res, std::move(*this));
          return;
        case status::connecting:
        case status::resolving:
          assert(0);
        case status::receiving:
        case status::closing:
          break;
        }
      }
      this->complete_now(ec, response<>(data.res));
    }

    void operator()(beast::error_code ec, tcp::resolver::results_type results)
    {
      if (ec)
      {
        this->complete_now(ec, data.res);
        return;
      }
      state = status::connecting;
      beast::get_lowest_layer(data.stream)
          .async_connect(results, std::move(*this));
    }

    void operator()(beast::error_code ec,
                    tcp::resolver::results_type::endpoint_type endpoint)
    {
      if (ec)
      {
        this->complete_now(ec, data.res);
        return;
      }
      state = status::handshaking;
      data.stream.async_handshake(ssl::stream_base::client, std::move(*this));
    }
  };

  net::async_completion<CompletionHandler, void(beast::error_code, response<>)>
      init{handler};
  composer(std::move(host), stream, req, res, init.completion_handler);
  return init.result.get();
}
}
}
