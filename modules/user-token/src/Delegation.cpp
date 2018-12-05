#include <Tanker/UserToken/Delegation.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Crypto/Types.hpp>
#include <Tanker/Types/UserId.hpp>

#include <array>
#include <cstdint>
#include <tuple>
#include <vector>

namespace Tanker
{
namespace UserToken
{
Delegation makeDelegation(
    UserId const& userId,
    Crypto::PrivateSignatureKey const& privateSignatureKey)
{
  Delegation delegation{};

  delegation.ephemeralKeyPair = Crypto::makeSignatureKeyPair();
  delegation.userId = userId;

  std::vector<uint8_t> toSign;
  toSign.insert(toSign.end(),
                delegation.ephemeralKeyPair.publicKey.begin(),
                delegation.ephemeralKeyPair.publicKey.end());
  toSign.insert(
      toSign.end(), delegation.userId.begin(), delegation.userId.end());
  delegation.signature = Crypto::sign(toSign, privateSignatureKey);

  return delegation;
}

bool operator==(Delegation const& lhs, Delegation const& rhs) noexcept
{
  return std::tie(lhs.userId, lhs.ephemeralKeyPair, lhs.signature) ==
         std::tie(rhs.userId, rhs.ephemeralKeyPair, rhs.signature);
}

bool operator!=(Delegation const& lhs, Delegation const& rhs) noexcept
{
  return !(lhs == rhs);
}
}
}
