#pragma once

#include <Tanker/AConnection.hpp>

#include <sio_client.h>
#include <tconcurrent/coroutine.hpp>
#include <tconcurrent/task_auto_canceler.hpp>

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

  Connection(std::string url);

  bool isOpen() const override;
  void connect() override;

  tc::cotask<std::string> emit(std::string const& eventName,
                               std::string const& data) override;

  void on(std::string const& message, AConnection::Handler handler) override;

private:
  std::string _trustchainUrl;

  tc::task_auto_canceler _taskCanceler;
  sio::client _client;
};

} // Tanker
