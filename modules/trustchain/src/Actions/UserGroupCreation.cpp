#include <Tanker/Trustchain/Actions/UserGroupCreation.hpp>

#include <algorithm>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
Nature UserGroupCreation::nature() const
{
  return mpark::visit([](auto const& a) { return a.nature(); }, _variant);
}

std::vector<std::uint8_t> UserGroupCreation::signatureData() const
{
  return mpark::visit([&](auto const& val) { return val.signatureData(); },
                      _variant);
}

Crypto::Signature const& UserGroupCreation::selfSign(
    Crypto::PrivateSignatureKey const& key)
{
  return mpark::visit(
      [&](auto& val) -> decltype(auto) { return val.selfSign(key); }, _variant);
}
}
}
}
