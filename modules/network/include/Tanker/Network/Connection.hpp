#pragma once

#include <Tanker/Network/AConnection.hpp>
#include <Tanker/Network/QueryParameters.hpp>
#include <Tanker/Network/SdkInfo.hpp>

#include <tconcurrent/coroutine.hpp>
#include <tconcurrent/task_auto_canceler.hpp>

#include <sio_client.h>

#include <string>

namespace Tanker
{
namespace Network
{
class Connection : public AConnection
{
public:
  Connection(Connection&&) = delete;
  Connection(Connection const&) = delete;
  Connection& operator=(Connection const&) = delete;
  Connection& operator=(Connection&&) = delete;

  Connection(std::string url, SdkInfo);
  Connection(std::string url, std::string context);

  bool isOpen() const override;
  void connect() override;
  std::string id() const override;

  tc::cotask<std::string> emit(std::string const& eventName,
                               std::string const& data) override;

  void on(std::string const& message, AConnection::Handler handler) override;

private:
  Connection(std::string url, QueryParameters);

  std::string const _url;
  QueryParameters const _params;

  tc::task_auto_canceler _taskCanceler;
  sio::client _client;
};
}
}
