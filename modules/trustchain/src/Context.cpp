#include <Tanker/Trustchain/Context.hpp>

namespace Tanker::Trustchain
{
Context::Context(TrustchainId const& id, Crypto::PublicSignatureKey const& publicSignatureKey)
  : _id(id), _publicSignatureKey(publicSignatureKey)
{
}

TrustchainId const& Context::id() const
{
  return _id;
}

Crypto::PublicSignatureKey const& Context::publicSignatureKey() const
{
  return _publicSignatureKey;
}
}
