#pragma once

#include <tconcurrent/coroutine.hpp>

#include <functional>
#include <memory>
#include <string>

namespace Tanker
{
class AConnection
{
public:
  using Handler = std::function<void(std::string const&)>;

  virtual bool isOpen() const = 0;
  virtual void connect() = 0;
  virtual std::string id() const = 0;

  virtual tc::cotask<std::string> emit(std::string const& eventName,
                                       std::string const& data) = 0;

  virtual void on(std::string const& message, Handler handler) = 0;
  virtual ~AConnection() = default;

  std::function<void()> connected;
  std::function<void()> reconnected;
};

using ConnectionPtr = std::unique_ptr<AConnection>;
}
