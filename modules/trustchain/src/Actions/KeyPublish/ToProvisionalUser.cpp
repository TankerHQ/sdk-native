#include <Tanker/Trustchain/Actions/KeyPublish/ToProvisionalUser.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Serialization/Serialization.hpp>

#include <nlohmann/json.hpp>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
KeyPublishToProvisionalUser::KeyPublishToProvisionalUser(
    TrustchainId const& trustchainId,
    Crypto::PublicSignatureKey const& appPublicSignatureKey,
    Crypto::PublicSignatureKey const& tankerPublicSignatureKey,
    ResourceId const& resourceId,
    Crypto::TwoTimesSealedSymmetricKey const& twoTimesSealedSymmetricKey,
    Crypto::Hash const& author,
    Crypto::PrivateSignatureKey const& devicePrivateSignatureKey)
  : _trustchainId(trustchainId),
    _appPublicSignatureKey(appPublicSignatureKey),
    _tankerPublicSignatureKey(tankerPublicSignatureKey),
    _resourceId(resourceId),
    _twoTimesSealedSymmetricKey(twoTimesSealedSymmetricKey),
    _author(author),
    _hash(computeHash()),
    _signature(Crypto::sign(_hash, devicePrivateSignatureKey))
{
}

TANKER_TRUSTCHAIN_ACTION_DEFINE_PAYLOAD_SIZE(
    KeyPublishToProvisionalUser,
    TANKER_TRUSTCHAIN_ACTIONS_KEY_PUBLISH_TO_PROVISIONAL_USER_ATTRIBUTES)
TANKER_TRUSTCHAIN_ACTION_DEFINE_HASH(
    KeyPublishToProvisionalUser,
    TANKER_TRUSTCHAIN_ACTIONS_KEY_PUBLISH_TO_PROVISIONAL_USER_ATTRIBUTES)
TANKER_TRUSTCHAIN_ACTION_DEFINE_SERIALIZATION_2(
    KeyPublishToProvisionalUser,
    TANKER_TRUSTCHAIN_ACTIONS_KEY_PUBLISH_TO_PROVISIONAL_USER_ATTRIBUTES)
TANKER_TRUSTCHAIN_ACTION_DEFINE_TO_JSON(
    KeyPublishToProvisionalUser,
    TANKER_TRUSTCHAIN_ACTIONS_KEY_PUBLISH_TO_PROVISIONAL_USER_ATTRIBUTES)
}
}
}
