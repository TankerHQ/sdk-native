#pragma once

#include <Tanker/Trustchain/ServerEntry.hpp>
#include <Tanker/Trustchain/TrustchainId.hpp>

#include <tconcurrent/coroutine.hpp>

#include <vector>

namespace Tanker::Users
{
class LocalUser;

struct UserStatusResult
{
  bool deviceExists;
  bool userExists;
  Crypto::Hash lastReset;
};

class IRequester
{
public:
  virtual ~IRequester() = default;
  virtual tc::cotask<void> authenticate(
      Trustchain::TrustchainId const& trustchainId,
      LocalUser const& localUser) = 0;
  virtual tc::cotask<UserStatusResult> userStatus(
      Trustchain::TrustchainId const& trustchainId,
      Trustchain::UserId const& userId,
      Crypto::PublicSignatureKey const& publicSignatureKey) = 0;
};
}
