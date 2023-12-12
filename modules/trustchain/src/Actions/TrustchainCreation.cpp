#include <Tanker/Trustchain/Actions/TrustchainCreation.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Trustchain/Errors/Errc.hpp>
#include <Tanker/Trustchain/Serialization.hpp>
#include <Tanker/Trustchain/TrustchainId.hpp>

#include <nlohmann/json.hpp>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
TrustchainCreation::TrustchainCreation(Crypto::PublicSignatureKey const& publicSignatureKey)
  : _publicSignatureKey(publicSignatureKey), _author(), _hash(computeHash()), _signature()
{
  std::copy(_hash.begin(), _hash.end(), _trustchainId.begin());
}

TANKER_TRUSTCHAIN_ACTION_DEFINE_METHODS(TrustchainCreation, TANKER_TRUSTCHAIN_ACTIONS_TRUSTCHAIN_CREATION_ATTRIBUTES)
}
}
}
