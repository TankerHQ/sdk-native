#include <Tanker/Trustchain/Actions/TrustchainCreation.hpp>
#include <Tanker/Serialization/Serialization.hpp>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
void from_serialized(Serialization::SerializedSource& ss,
                     TrustchainCreation& tc)
{
  Serialization::deserialize_to(ss, tc._publicSignatureKey);
}

std::uint8_t* to_serialized(std::uint8_t* it, TrustchainCreation const& tc)
{
  return Serialization::serialize(it, tc.publicSignatureKey());
}
}
}
}
