#include <Tanker/Trustchain/Actions/TrustchainCreation.hpp>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
TrustchainCreation::TrustchainCreation(
    Crypto::PublicSignatureKey const& publicSignatureKey)
  : _publicSignatureKey(publicSignatureKey)
{
}

Crypto::PublicSignatureKey const& TrustchainCreation::publicSignatureKey() const
{
  return _publicSignatureKey; 
}

bool operator==(TrustchainCreation const& lhs, TrustchainCreation const& rhs)
{
  return lhs.publicSignatureKey() == rhs.publicSignatureKey();
}

bool operator!=(TrustchainCreation const& lhs, TrustchainCreation const& rhs)
{
  return !(lhs == rhs);
}
}
}
}
