#include "BenchHelpers.hpp"

#include <Tanker/Identity/PublicIdentity.hpp>
#include <Tanker/Identity/SecretPermanentIdentity.hpp>

using namespace Tanker::Functional;

Trustchain& getTrustchain()
{
  static auto& trustchain = TrustchainFixture{}.trustchain;
  return trustchain;
}

std::string makePublicIdentity(std::string const& sappId, uint32_t n)
{
  auto appId = mgs::base64::decode<Tanker::Trustchain::TrustchainId>(sappId);
  auto const publicIdentity = Tanker::Identity::PublicPermanentIdentity{
      appId,
      Tanker::obfuscateUserId(Tanker::SUserId(std::to_string(n)), appId),
  };
  return to_string(publicIdentity);
}

Tanker::SUserId createRandomUserId()
{
  auto rdm = std::array<std::uint8_t, 10>{};
  Tanker::Crypto::randomFill(rdm);
  return Tanker::SUserId{mgs::base64::encode(rdm)};
}
