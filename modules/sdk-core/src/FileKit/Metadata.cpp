#include <Tanker/FileKit/Metadata.hpp>

#include <Tanker/Encryptor/v5.hpp>
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
    Metadata const& metadata,
    Trustchain::ResourceId const& resourceId,
    Crypto::SymmetricKey const& key)
{
  auto const jmetadata = nlohmann::json(metadata).dump();

  std::vector<uint8_t> encryptedMetadata(
      EncryptorV5::encryptedSize(jmetadata.size()));
  EncryptorV5::encrypt(encryptedMetadata.data(),
                       gsl::make_span(jmetadata).as_span<uint8_t const>(),
                       resourceId,
                       key);
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
