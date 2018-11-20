#pragma once

#include <Tanker/AConnection.hpp>

#include <nlohmann/json.hpp>
#include <trompeloeil.hpp>

#include <map>

namespace Tanker
{
class MockConnection : public AConnection
{
public:
  MockConnection();
  // bool isOpen() const override;
  MAKE_CONST_MOCK0(isOpen, bool(), override);
  // void connect() override;
  MAKE_MOCK0(connect, void(), override);
  // tc::cotask<std::string> emit(
  // std::string const& eventName,
  // std::string const& data) override;
  MAKE_MOCK2(emit,
             tc::cotask<std::string>(std::string const&, std::string const&),
             override);
  // void on(std::string const& message, AConnection::Handler handler) override;
  MAKE_MOCK2(on,
             void(std::string const&, std::function<void(std::string const&)>),
             override);
  MAKE_MOCK0(wasConnected, void());
};
}
