#include <Tanker/Network/JsConnection.hpp>

#include <Tanker/Log/Log.hpp>

#include <fmt/format.h>
#include <tconcurrent/promise.hpp>

#include <emscripten.h>
#include <emscripten/bind.h>

TLOG_CATEGORY(JsConnection);

namespace Tanker
{
namespace Network
{
class JsConnectionInterface
{
public:
  virtual ~JsConnectionInterface() = default;
  virtual void connect() = 0;
  virtual std::string id() = 0;
  virtual void emit(std::string const& eventName,
                    std::string const& data,
                    std::function<void(std::string const&)> const& cb) = 0;
  virtual void on(std::string const& eventName,
                  std::function<void(std::string const&)> const& cb) = 0;

  void onConnected()
  {
    connected();
  }
  void onReconnected()
  {
    reconnected();
  }

  std::function<void()> connected;
  std::function<void()> reconnected;
};
}
}

namespace
{
class JsConnectionInterfaceWrapper
  : public emscripten::wrapper<Tanker::Network::JsConnectionInterface>
{
public:
  EMSCRIPTEN_WRAPPER(JsConnectionInterfaceWrapper);

  void connect() override
  {
    return call<void>("connect");
  }
  std::string id() override
  {
    return call<std::string>("id");
  }
  void emit(std::string const& eventName,
            std::string const& data,
            std::function<void(std::string const&)> const& cb) override
  {
    return call<void>("emit", eventName, data, cb);
  }
  void on(std::string const& eventName,
          std::function<void(std::string const&)> const& cb) override
  {
    return call<void>("on", eventName, cb);
  }
};

std::function<std::unique_ptr<Tanker::Network::JsConnectionInterface>(
    std::string const& url)>
    jsConnectionFactory;

void setJsConnectionFactory(emscripten::val factory)
{
  jsConnectionFactory = [=](std::string const& url) mutable {
    return factory(url)
        .as<std::unique_ptr<Tanker::Network::JsConnectionInterface>>();
  };
}
}

namespace Tanker
{
namespace Network
{
JsConnection::JsConnection(std::string url)
  : _trustchainUrl(std::move(url)), _conn(jsConnectionFactory(_trustchainUrl))
{
  _conn->connected = [this] {
    TINFO("Connected");
    _taskCanceler.add(tc::async([this] {
      if (connected)
        connected();
    }));
  };
  _conn->reconnected = [this] {
    TINFO("Reconnected");
    _taskCanceler.add(tc::async([this] {
      if (reconnected)
        reconnected();
    }));
  };
}

JsConnection::~JsConnection() = default;

bool JsConnection::isOpen() const
{
  return true;
}

void JsConnection::connect()
{
  _conn->connect();
}

std::string JsConnection::id() const
{
  return _conn->id();
}

void JsConnection::on(std::string const& eventName,
                      AConnection::Handler handler)
{
  TDEBUG("on({})", eventName);
  _conn->on(eventName, [=](std::string const& data) {
    _taskCanceler.add(tc::async([=] {
      try
      {
        TINFO("on({}) = {}", eventName, data);
        handler(data);
      }
      catch (std::exception const& e)
      {
        TERROR("Error in handling signal {}: {}", eventName, e.what());
      }
    }));
  });
}

tc::cotask<std::string> JsConnection::emit(std::string const& eventName,
                                           std::string const& data)
{
  TDEBUG("emit({}, {})", eventName, data);
  auto prom = tc::promise<std::string>();
  auto future = prom.get_future();
  _conn->emit(
      eventName.c_str(),
      data.c_str(),
      [prom = std::move(prom)](std::string const& stringmessage) mutable {
        prom.set_value(stringmessage);
      });
  TC_RETURN(TC_AWAIT(std::move(future)));
}
}
}

EMSCRIPTEN_BINDINGS(jsconnectioninterface)
{
  using namespace Tanker::Network;

  emscripten::class_<std::function<void(std::string const&)>>("SioCbFunction")
      .constructor<>()
      .function("opcall", &std::function<void(std::string const&)>::operator());

  emscripten::class_<JsConnectionInterface>("JsConnectionInterface")
      .function("connect", &JsConnectionInterface::connect)
      .function("id", &JsConnectionInterface::id)
      .function("onConnected", &JsConnectionInterface::onConnected)
      .function("onReconnected", &JsConnectionInterface::onReconnected)
      .function(
          "emit", &JsConnectionInterface::emit, emscripten::pure_virtual())
      .function("on", &JsConnectionInterface::on, emscripten::pure_virtual())
      .allow_subclass<JsConnectionInterfaceWrapper>(
          "JsConnectionInterfaceWrapper");

  emscripten::function("setJsConnectionFactory", &setJsConnectionFactory);
}
