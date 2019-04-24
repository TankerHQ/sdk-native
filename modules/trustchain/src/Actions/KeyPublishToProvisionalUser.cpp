#include <Tanker/Trustchain/Actions/KeyPublishToProvisionalUser.hpp>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
KeyPublishToProvisionalUser::KeyPublishToProvisionalUser(
    Crypto::PublicSignatureKey const& appPublicSignatureKey,
    ResourceId const& resourceId,
    Crypto::PublicSignatureKey const& tankerPublicSignatureKey,
    Crypto::TwoTimesSealedSymmetricKey const& twoTimesSealedSymmetricKey)
  : _appPublicSignatureKey(appPublicSignatureKey),
    _tankerPublicSignatureKey(tankerPublicSignatureKey),
    _resourceId(resourceId),
    _twoTimesSealedSymmetricKey(twoTimesSealedSymmetricKey)
{
}

Crypto::PublicSignatureKey const&
KeyPublishToProvisionalUser::appPublicSignatureKey() const
{
  return _appPublicSignatureKey;
}

Crypto::PublicSignatureKey const&
KeyPublishToProvisionalUser::tankerPublicSignatureKey() const
{
  return _tankerPublicSignatureKey;
}

ResourceId const& KeyPublishToProvisionalUser::resourceId() const
{
  return _resourceId;
}

Crypto::TwoTimesSealedSymmetricKey const&
KeyPublishToProvisionalUser::twoTimesSealedSymmetricKey() const
{
  return _twoTimesSealedSymmetricKey;
}

bool operator==(KeyPublishToProvisionalUser const& lhs,
                KeyPublishToProvisionalUser const& rhs)
{
  return std::tie(lhs.appPublicSignatureKey(),
                  lhs.tankerPublicSignatureKey(),
                  lhs.resourceId(),
                  lhs.twoTimesSealedSymmetricKey()) ==
         std::tie(rhs.appPublicSignatureKey(),
                  rhs.tankerPublicSignatureKey(),
                  rhs.resourceId(),
                  rhs.twoTimesSealedSymmetricKey());
}

bool operator!=(KeyPublishToProvisionalUser const& lhs,
                KeyPublishToProvisionalUser const& rhs)
{
  return !(lhs == rhs);
}
}
}
}
