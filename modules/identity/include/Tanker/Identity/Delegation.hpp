#pragma once

#include <Tanker/Crypto/Signature.hpp>
#include <Tanker/Crypto/SignatureKeyPair.hpp>
#include <Tanker/Trustchain/UserId.hpp>

namespace Tanker
{
namespace Identity
{
struct Delegation
{
  Crypto::SignatureKeyPair ephemeralKeyPair;
  Trustchain::UserId userId;
  Crypto::Signature signature;
};

Delegation makeDelegation(Trustchain::UserId const& userId, Crypto::PrivateSignatureKey const& privateSignatureKey);

bool operator==(Delegation const&, Delegation const&) noexcept;
bool operator!=(Delegation const&, Delegation const&) noexcept;
}
}
