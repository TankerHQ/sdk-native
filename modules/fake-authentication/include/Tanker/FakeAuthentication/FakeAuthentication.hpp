#pragma once

#include <tccurl/curl.hpp>

#include <tconcurrent/coroutine.hpp>

#include <nlohmann/json_fwd.hpp>

#include <optional.hpp>

#include <string>
#include <vector>

namespace Tanker
{
namespace FakeAuthentication
{
struct PrivateIdentity
{
  std::string permanentIdentity;
  nonstd::optional<std::string> provisionalIdentity;
};

void from_json(nlohmann::json const& j, PrivateIdentity& result);

class FakeAuthentication
{
public:
  FakeAuthentication(
      std::string const& appId,
      nonstd::optional<std::string> const& url = nonstd::nullopt);

  tc::cotask<PrivateIdentity> getPrivateIdentity(
      nonstd::optional<std::string> const& email = nonstd::nullopt);

  tc::cotask<std::vector<std::string>> getPublicIdentities(
      std::vector<std::string> const& emails);

private:
  tccurl::multi _multi;

  std::string _baseUrl;
};
}
}
