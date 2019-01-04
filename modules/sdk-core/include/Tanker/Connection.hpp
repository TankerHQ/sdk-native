#pragma once

#include <Tanker/AConnection.hpp>
#include <Tanker/SdkInfo.hpp>

#include <tconcurrent/coroutine.hpp>
#include <tconcurrent/task_auto_canceler.hpp>

#include <sio_client.h>

#include <optional.hpp>
#include <string>

namespace Tanker
{
class Connection : public AConnection
{
public:
  Connection(Connection&&) = delete;
  Connection(Connection const&) = delete;
  Connection& operator=(Connection const&) = delete;
  Connection& operator=(Connection&&) = delete;

  Connection(std::string url, nonstd::optional<SdkInfo>);

  bool isOpen() const override;
  void connect() override;
  std::string id() const override;

  tc::cotask<std::string> emit(std::string const& eventName,
                               std::string const& data) override;

  void on(std::string const& message, AConnection::Handler handler) override;

private:
  std::string _url;
  nonstd::optional<SdkInfo> _infos;

  tc::task_auto_canceler _taskCanceler;
  sio::client _client;
};

} // Tanker
