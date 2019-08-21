#include <Tanker/FileKit/Metadata.hpp>

#include <Tanker/Session.hpp>

#include <nlohmann/json.hpp>

namespace Tanker
{
namespace FileKit
{
namespace
{
template <typename T>
nonstd::optional<T> getJsonOptional(nlohmann::json const& j,
                                    std::string const& name)
{
  auto it = j.find(name);
  if (it == j.end())
    return nonstd::nullopt;
  if (it->is_null())
    return nonstd::nullopt;
  return it->get<T>();
}
}
void from_json(nlohmann::json const& j, Metadata& m)
{
  m.mime = getJsonOptional<std::string>(j, "mime");
  m.name = getJsonOptional<std::string>(j, "name");
  auto const lastModified = getJsonOptional<uint64_t>(j, "lastModified");
  if (lastModified)
    m.lastModified = std::chrono::milliseconds(*lastModified);
}
void to_json(nlohmann::json& j, Metadata const& m)
{
  if (m.mime)
    j["mime"] = *m.mime;
  if (m.name)
    j["name"] = *m.name;
  if (m.lastModified)
    j["lastModified"] = m.lastModified->count();
}

tc::cotask<std::string> encryptMetadata(
    Session& session,
    Metadata const& metadata,
    std::vector<SPublicIdentity> const& publicIdentities,
    std::vector<SGroupId> const& groupIds)
{
  auto const jmetadata = nlohmann::json(metadata).dump();
  auto const encryptedMetadata = TC_AWAIT(
      session.encrypt(gsl::make_span(jmetadata).as_span<uint8_t const>(),
                      publicIdentities,
                      groupIds));
  TC_RETURN(cppcodec::base64_rfc4648::encode(encryptedMetadata));
}

tc::cotask<Metadata> decryptMetadata(Session& session,
                                     std::string const& sencryptedMetadata)
{
  auto const encryptedMetadata =
      cppcodec::base64_rfc4648::decode(sencryptedMetadata);
  auto const decryptedMetadata = TC_AWAIT(session.decrypt(encryptedMetadata));
  TC_RETURN(
      nlohmann::json::parse(decryptedMetadata.begin(), decryptedMetadata.end())
          .get<Metadata>());
}
}
}
