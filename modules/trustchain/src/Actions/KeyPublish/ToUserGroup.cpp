#include <Tanker/Trustchain/Actions/KeyPublish/ToUserGroup.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Trustchain/Serialization.hpp>

#include <nlohmann/json.hpp>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
KeyPublishToUserGroup::KeyPublishToUserGroup(TrustchainId const& trustchainId,
                                             Crypto::PublicEncryptionKey const& recipientPublicEncryptionKey,
                                             Crypto::SimpleResourceId const& resourceId,
                                             Crypto::SealedSymmetricKey const& sealedSymmetricKey,
                                             Crypto::Hash const& author,
                                             Crypto::PrivateSignatureKey const& devicePrivateSignatureKey)
  : _trustchainId(trustchainId),
    _recipientPublicEncryptionKey(recipientPublicEncryptionKey),
    _resourceId(resourceId),
    _sealedSymmetricKey(sealedSymmetricKey),
    _author(author),
    _hash(computeHash()),
    _signature(Crypto::sign(_hash, devicePrivateSignatureKey))
{
}

TANKER_TRUSTCHAIN_ACTION_DEFINE_METHODS(KeyPublishToUserGroup,
                                        TANKER_TRUSTCHAIN_ACTIONS_KEY_PUBLISH_TO_USER_GROUP_ATTRIBUTES)
}
}
}
