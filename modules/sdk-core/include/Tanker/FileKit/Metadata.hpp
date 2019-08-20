#pragma once

#include <Tanker/Trustchain/ResourceId.hpp>
#include <Tanker/Types/SGroupId.hpp>
#include <Tanker/Types/SPublicIdentity.hpp>

#include <nlohmann/json_fwd.hpp>
#include <optional.hpp>
#include <tconcurrent/coroutine.hpp>

#include <chrono>
#include <string>

namespace Tanker
{
class Session;
namespace FileKit
{
struct Metadata
{
  nonstd::optional<std::string> mime;
  nonstd::optional<std::string> name;
  nonstd::optional<std::chrono::milliseconds> lastModified;
};

void from_json(nlohmann::json const& j, Metadata& m);
void to_json(nlohmann::json& j, Metadata const& m);

tc::cotask<std::string> encryptMetadata(
    Session& session,
    Metadata const& metadata,
    std::vector<SPublicIdentity> const& publicIdentities = {},
    std::vector<SGroupId> const& groupIds = {});

tc::cotask<Metadata> decryptMetadata(Session& session,
                                     std::string const& sencryptedMetadata);
}
}
