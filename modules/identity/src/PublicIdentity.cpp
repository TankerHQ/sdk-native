#include <Tanker/Identity/PublicIdentity.hpp>

#include <Tanker/Errors/AssertionError.hpp>
#include <Tanker/Identity/Extract.hpp>
#include <Tanker/Identity/PublicPermanentIdentity.hpp>
#include <Tanker/Identity/PublicProvisionalIdentity.hpp>
#include <Tanker/Identity/SecretIdentity.hpp>

#include <nlohmann/json.hpp>
#include <range/v3/algorithm/all_of.hpp>
#include <range/v3/functional/bind_back.hpp>

namespace Tanker
{
namespace Identity
{
PublicIdentity getPublicIdentity(SecretPermanentIdentity const& identity)
{
  return PublicIdentity(PublicPermanentIdentity{identity.trustchainId, identity.delegation.userId});
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
    auto const hashedEmail = hashProvisionalEmail(prov.value);
    prov.value = mgs::base64::encode(hashedEmail);
  }
  else if (prov.target == TargetType::PhoneNumber)
  {
    prov.target = TargetType::HashedPhoneNumber;
    auto const hashedPhoneNumber = hashProvisionalPhoneNumber(identity);
    prov.value = mgs::base64::encode(hashedPhoneNumber);
  }
  else
  {
    throw Errors::AssertionError(fmt::format("unsupported target type: {}", static_cast<int>(prov.target)));
  }
  return prov;
}

std::string getPublicIdentity(std::string const& secretIdentity)
{
  return to_string(boost::variant2::visit([](auto const& i) { return getPublicIdentity(i); },
                                          extract<SecretIdentity>(secretIdentity)));
}

void ensureIdentitiesInTrustchain(std::vector<PublicIdentity> const& publicIdentities,
                                  Trustchain::TrustchainId const& trustchainId)
{
  auto proj = [](auto const& identity) {
    return boost::variant2::visit(
        [](auto const& identity) -> Trustchain::TrustchainId const& { return identity.trustchainId; }, identity);
  };

  auto pred = ranges::bind_back(std::equal_to{}, trustchainId);

  if (!ranges::all_of(publicIdentities, pred, proj))
  {
    throw Errors::formatEx(Errors::Errc::InvalidArgument, "public identity not in the trustchain");
  }
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
  boost::variant2::visit([&](auto const& i) { nlohmann::to_json(j, i); }, identity);
}

std::string to_string(PublicIdentity const& identity)
{
  return boost::variant2::visit([](auto const& i) { return to_string(i); }, identity);
}
}
}
