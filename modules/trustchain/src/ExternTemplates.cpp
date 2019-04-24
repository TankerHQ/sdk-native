#include <Tanker/Trustchain/DeviceId.hpp>
#include <Tanker/Trustchain/GroupId.hpp>
#include <Tanker/Trustchain/TrustchainId.hpp>
#include <Tanker/Trustchain/UserId.hpp>

namespace Tanker
{
namespace Crypto
{
template class BasicHash<struct Trustchain::detail::DeviceIdImpl>;
template class BasicHash<struct Trustchain::detail::UserIdImpl>;
template class BasicHash<struct Trustchain::detail::TrustchainIdImpl>;
template class BasicCryptographicType<Trustchain::GroupId,
                                      PublicSignatureKey::arraySize>;
}
}
