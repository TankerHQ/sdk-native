#pragma once

#include <Tanker/Crypto/SealedPrivateEncryptionKey.hpp>
#include <Tanker/Crypto/SignatureKeyPair.hpp>
#include <Tanker/Trustchain/Actions/TrustchainCreation.hpp>
#include <Tanker/Trustchain/DeviceId.hpp>
#include <Tanker/Trustchain/KeyPublishAction.hpp>
#include <Tanker/Trustchain/ResourceId.hpp>
#include <Tanker/Trustchain/TrustchainId.hpp>
#include <Tanker/Trustchain/UserAction.hpp>
#include <Tanker/Trustchain/UserId.hpp>
#include <Tanker/Types/Email.hpp>
#include <Tanker/Types/HashedEmail.hpp>

#include <tconcurrent/coroutine.hpp>

#include <gsl/gsl-lite.hpp>

#include <map>
#include <utility>
#include <vector>

namespace Tanker::Share
{
struct ShareActions;
}

namespace Tanker::Users
{
class IRequester
{
public:
  struct GetResult
  {
    Trustchain::Actions::TrustchainCreation trustchainCreation;
    std::vector<Trustchain::UserAction> userEntries;
  };

  struct GetEncryptionKeyResult
  {
    Crypto::SealedPrivateEncryptionKey encryptedUserPrivateEncryptionKey;
    Trustchain::DeviceId ghostDeviceId;
  };

  enum class IsLight
  {
    No,
    Yes,
  };

  virtual ~IRequester() = default;
  virtual tc::cotask<IRequester::GetResult> getRevokedDeviceHistory(
      Trustchain::DeviceId const& deviceId) = 0;
  virtual tc::cotask<GetResult> getUsers(
      gsl::span<Trustchain::UserId const> userIds, IsLight isLight) = 0;
  virtual tc::cotask<GetResult> getUsers(
      gsl::span<Trustchain::DeviceId const> deviceIds, IsLight isLight) = 0;
  virtual tc::cotask<std::vector<Trustchain::KeyPublishAction>> getKeyPublishes(
      gsl::span<Trustchain::ResourceId const> resourceIds) = 0;
  virtual tc::cotask<void> postResourceKeys(
      Share::ShareActions const& resourceKeys) = 0;
  virtual tc::cotask<GetEncryptionKeyResult> getEncryptionKey(
      Trustchain::UserId const& userId,
      Crypto::PublicSignatureKey const& ghostDevicePublicSignatureKey) = 0;
  virtual tc::cotask<void> revokeDevice(
      Trustchain::Actions::DeviceRevocation const& deviceRevocation) = 0;
  virtual tc::cotask<std::map<
      HashedEmail,
      std::pair<Crypto::PublicSignatureKey, Crypto::PublicEncryptionKey>>>
  getPublicProvisionalIdentities(gsl::span<HashedEmail const> hashedEmails) = 0;
};
}
