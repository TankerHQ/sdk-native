#include <Tanker/Crypto/ResourceId.hpp>
#include <Tanker/Trustchain/DeviceId.hpp>
#include <Tanker/Trustchain/GroupId.hpp>
#include <Tanker/Trustchain/HashedPassphrase.hpp>
#include <Tanker/Trustchain/TrustchainId.hpp>
#include <Tanker/Trustchain/UserId.hpp>

namespace Tanker
{
namespace Crypto
{
template class BasicHash<struct Trustchain::detail::DeviceIdImpl>;
template class BasicHash<struct Trustchain::detail::UserIdImpl>;
template class BasicHash<struct Trustchain::detail::TrustchainIdImpl>;
template class BasicHash<struct Trustchain::detail::HashedPassphraseImpl>;
template class BasicCryptographicType<Trustchain::GroupId,
                                      PublicSignatureKey::arraySize>;
template class BasicCryptographicType<Crypto::ResourceId, Mac::arraySize>;
}
}
