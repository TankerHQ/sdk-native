#pragma once

#include <Tanker/Types/UserId.hpp>

namespace Tanker
{
namespace Identity
{
struct Delegation
{
  Crypto::SignatureKeyPair ephemeralKeyPair;
  UserId userId;
  Crypto::Signature signature;
};

Delegation makeDelegation(
    UserId const& userId,
    Crypto::PrivateSignatureKey const& privateSignatureKey);

bool operator==(Delegation const&, Delegation const&) noexcept;
bool operator!=(Delegation const&, Delegation const&) noexcept;
}
}
