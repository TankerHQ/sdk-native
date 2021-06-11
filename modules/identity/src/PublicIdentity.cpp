#include <Tanker/Identity/PublicIdentity.hpp>

#include <Tanker/Identity/Extract.hpp>
#include <Tanker/Identity/PublicPermanentIdentity.hpp>
#include <Tanker/Identity/PublicProvisionalIdentity.hpp>
#include <Tanker/Identity/SecretIdentity.hpp>

#include <nlohmann/json.hpp>

namespace Tanker
{
namespace Identity
{
PublicIdentity getPublicIdentity(SecretPermanentIdentity const& identity)
{
  return PublicIdentity(PublicPermanentIdentity{identity.trustchainId,
                                                identity.delegation.userId});
}

PublicIdentity getPublicIdentity(SecretProvisionalIdentity const& identity)
{
  auto prov = PublicProvisionalIdentity{
      identity.trustchainId,
      identity.target,
      identity.value,
      identity.appSignatureKeyPair.publicKey,
      identity.appEncryptionKeyPair.publicKey,
  };
  if (prov.target == TargetType::Email)
  {
    prov.target = TargetType::HashedEmail;
    auto hashedEmail = Crypto::generichash(
        gsl::make_span(prov.value).as_span<uint8_t const>());
    prov.value = mgs::base64::encode(hashedEmail);
  }
  return prov;
}

std::string getPublicIdentity(std::string const& secretIdentity)
{
  return to_string(
      boost::variant2::visit([](auto const& i) { return getPublicIdentity(i); },
                             extract<SecretIdentity>(secretIdentity)));
}

void from_json(nlohmann::json const& j, PublicIdentity& identity)
{
  auto const target = j.at("target").get<std::string>();
  if (target == "user")
    identity = j.get<PublicPermanentIdentity>();
  else
    identity = j.get<PublicProvisionalIdentity>();
}

void to_json(nlohmann::json& j, PublicIdentity const& identity)
{
  boost::variant2::visit([&](auto const& i) { nlohmann::to_json(j, i); },
                         identity);
}

std::string to_string(PublicIdentity const& identity)
{
  return boost::variant2::visit([](auto const& i) { return to_string(i); },
                                identity);
}
}
}
