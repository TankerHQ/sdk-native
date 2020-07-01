#include <Tanker/Network/Connection.hpp>

#if TANKER_BUILD_WITH_SSL
#include <Tanker/Cacerts/InitSsl.hpp>
#endif

#include <Tanker/Log/Log.hpp>

#include <mgs/base64.hpp>
#include <sio_message.h>
#include <sio_socket.h>
#include <tconcurrent/async.hpp>
#include <tconcurrent/promise.hpp>

#include <exception>
#include <utility>

#include <Tanker/Tracer/FuncTracer.hpp>
#include <Tanker/Tracer/ScopeTimer.hpp>

TLOG_CATEGORY(Connection);

namespace Tanker
{
namespace Network
{
Connection::Connection(std::string url, SdkInfo info)
  : Connection(url,
               QueryParameters{std::move(info.sdkType),
                               std::move(info.trustchainId),
                               std::move(info.version),
                               std::nullopt})
{
}

Connection::Connection(std::string url, std::string context)
  : Connection(url,
               QueryParameters{
                   "admin", std::nullopt, std::nullopt, std::move(context)})
{
}

Connection::Connection(std::string url, QueryParameters params)
  : _url(std::move(url)),
    _params(std::move(params)),
#if TANKER_BUILD_WITH_SSL
    _client(Cacerts::get_ssl_context())
#else
    _client()
#endif
{
  TINFO("Connection to {}", _url);
  _client.set_socket_open_listener([this](auto const&) {
    FUNC_END(fmt::format("connected {}", reinterpret_cast<void*>(this)), Net);
    _taskCanceler.add(tc::async([this] {
      TINFO("Connected");
      if (connected)
        connected();
    }));
  });
  _client.set_reconnect_listener([this](auto const&, auto const&) {
    _taskCanceler.add(tc::async([this] {
      TINFO("Reconnected");
      if (reconnected)
        reconnected();
    }));
  });
  _client.set_fail_listener([]() { TERROR("socket.io failure"); });
}

bool Connection::isOpen() const
{
  return this->_client.opened();
}

std::string Connection::id() const
{
  return this->_client.get_sessionid();
}

void Connection::connect()
{
  FUNC_BEGIN(fmt::format("connect {}", (void*)(this)), Net);

  std::map<std::string, std::string> query = {{"type", _params.sdkType}};
  if (_params.version)
    query["version"] = _params.version.value();
  if (_params.trustchainId)
    query["trustchainId"] =
        mgs::base64::encode(_params.trustchainId.value());
  if (_params.context)
    query["context"] = _params.context.value();

  this->_client.connect(_url, query);
}

void Connection::close()
{
  _client.close();
}

void Connection::on(std::string const& eventName, AConnection::Handler handler)
{
  this->_client.socket()->on(
      eventName, sio::socket::event_listener([=](sio::event& event) {
        _taskCanceler.add(tc::async([=] {
          try
          {
            auto msg = event.get_message();
            auto const stringmessage =
                msg->get_flag() == sio::message::flag_string ?
                    msg->get_string() :
                    "";
            TINFO("{}::on({}) = {}",
                  _client.get_sessionid(),
                  eventName,
                  stringmessage);
            handler(stringmessage);
          }
          catch (std::exception const& e)
          {
            TERROR("Error in handling signal {}: {}", eventName, e.what());
          }
        }));

        if (event.need_ack())
          event.put_ack_message(std::string());
      }));
}

tc::cotask<std::string> Connection::emit(std::string const& eventName,
                                         std::string const& data)
{
  SCOPE_TIMER(fmt::format("emit {}", eventName), Net);
  TDEBUG("{}::emit({}, {})", _client.get_sessionid(), eventName, data);
  tc::promise<std::string> prom;
  auto future = prom.get_future();
  this->_client.socket()->emit(
      eventName,
      data,
      // it is important to move the future so that we don't keep a reference on
      // it and it may be broken
      [prom = std::move(prom),
       eventName](sio::message::list const& msg) mutable {
        try
        {
          auto const stringmessage =
              msg.size() > 0 &&
                      msg[0]->get_flag() == sio::message::flag_string ?
                  msg[0]->get_string() :
                  "";
          prom.set_value(stringmessage);
        }
        catch (...)
        {
          prom.set_exception(std::current_exception());
        }
      });
  TC_RETURN(TC_AWAIT(std::move(future)));
}
}
}
