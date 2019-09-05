#pragma once

#include <Tanker/Network/AConnection.hpp>

#include <tconcurrent/coroutine.hpp>
#include <tconcurrent/task_auto_canceler.hpp>

#include <nlohmann/json_fwd.hpp>

namespace Tanker
{
namespace Network
{
class JsConnectionInterface;

class JsConnection : public AConnection
{
public:
  JsConnection(JsConnection&&) = delete;
  JsConnection(JsConnection const&) = delete;
  JsConnection& operator=(JsConnection const&) = delete;
  JsConnection& operator=(JsConnection&&) = delete;

  JsConnection(std::string url);

  ~JsConnection();

  bool isOpen() const override;
  void connect() override;
  std::string id() const override;

  tc::cotask<std::string> emit(std::string const& eventName,
                               std::string const& data) override;

  void on(std::string const& message, AConnection::Handler handler) override;

private:
  std::string _trustchainUrl;

  std::unique_ptr<JsConnectionInterface> _conn;

  tc::task_auto_canceler _taskCanceler;
};
}
}
