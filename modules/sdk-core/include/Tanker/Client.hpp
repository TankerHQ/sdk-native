#pragma once

#include <Tanker/Crypto/EncryptionKeyPair.hpp>
#include <Tanker/Crypto/Hash.hpp>
#include <Tanker/Crypto/PublicSignatureKey.hpp>
#include <Tanker/Crypto/Signature.hpp>
#include <Tanker/Crypto/SignatureKeyPair.hpp>
#include <Tanker/EncryptedUserKey.hpp>
#include <Tanker/GhostDevice.hpp>
#include <Tanker/Identity/SecretPermanentIdentity.hpp>
#include <Tanker/Network/AConnection.hpp>
#include <Tanker/Trustchain/DeviceId.hpp>
#include <Tanker/Trustchain/GroupId.hpp>
#include <Tanker/Trustchain/ResourceId.hpp>
#include <Tanker/Trustchain/TrustchainId.hpp>
#include <Tanker/Trustchain/UserId.hpp>
#include <Tanker/Types/Email.hpp>
#include <Tanker/Types/TankerSecretProvisionalIdentity.hpp>
#include <Tanker/Types/VerificationCode.hpp>
#include <Tanker/Unlock/Verification.hpp>

#include <boost/variant2/variant.hpp>
#include <gsl-lite.hpp>
#include <nlohmann/json_fwd.hpp>
#include <tconcurrent/coroutine.hpp>
#include <tconcurrent/task_auto_canceler.hpp>

#include <optional>

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace Tanker
{
namespace ClientHelpers
{
nlohmann::json makeVerificationRequest(Unlock::Verification const& verification,
                                       Crypto::SymmetricKey const& userSecret);
}

struct UserStatusResult
{
  bool deviceExists;
  bool userExists;
  Crypto::Hash lastReset;
};

void from_json(nlohmann::json const& j, UserStatusResult& result);

class Client
{
public:
  Client(Client const&) = delete;
  Client(Client&&) = delete;
  Client& operator=(Client const&) = delete;
  Client& operator=(Client&&) = delete;

  using ConnectionHandler = std::function<tc::cotask<void>()>;

  Client(Network::ConnectionPtr conn, ConnectionHandler connectionHandler = {});

  void start();
  void setConnectionHandler(ConnectionHandler handler);
  tc::cotask<void> handleConnection();

  tc::cotask<void> pushBlock(gsl::span<uint8_t const> block);
  tc::cotask<void> pushKeys(gsl::span<std::vector<uint8_t> const> block);

  tc::cotask<void> createUser(
      Identity::SecretPermanentIdentity const& identity,
      gsl::span<uint8_t const> userCreation,
      gsl::span<uint8_t const> firstDevice,
      Unlock::Verification const& method,
      Crypto::SymmetricKey userSecret,
      gsl::span<uint8_t const> encryptedVerificationKey);

  tc::cotask<UserStatusResult> userStatus(
      Trustchain::TrustchainId const& trustchainId,
      Trustchain::UserId const& userId,
      Crypto::PublicSignatureKey const& publicSignatureKey);

  tc::cotask<void> setVerificationMethod(
      Trustchain::TrustchainId const& trustchainId,
      Trustchain::UserId const& userId,
      Unlock::Verification const& method,
      Crypto::SymmetricKey userSecret);
  tc::cotask<VerificationKey> fetchVerificationKey(
      Trustchain::TrustchainId const& trustchainId,
      Trustchain::UserId const& userId,
      Unlock::Verification const& method,
      Crypto::SymmetricKey userSecret);

  tc::cotask<std::string> requestAuthChallenge();
  tc::cotask<void> authenticateDevice(nlohmann::json const& request);
  tc::cotask<std::vector<Unlock::VerificationMethod>> fetchVerificationMethods(
      Trustchain::TrustchainId const& trustchainId,
      Trustchain::UserId const& userId,
      Crypto::SymmetricKey const& userSecret);
  tc::cotask<EncryptedUserKey> getLastUserKey(
      Trustchain::TrustchainId const& trustchainId,
      Crypto::PublicSignatureKey const& devicePublicUserKey);

  tc::cotask<std::vector<std::string>> getBlocks(
      int index,
      std::vector<Trustchain::UserId> const& extra_users,
      std::vector<Trustchain::GroupId> const& extra_groups);

  tc::cotask<std::vector<std::string>> getKeyPublishes(
      gsl::span<Trustchain::ResourceId const> resourceIds);

  tc::cotask<std::vector<
      std::pair<Crypto::PublicSignatureKey, Crypto::PublicEncryptionKey>>>
  getPublicProvisionalIdentities(gsl::span<Email const>);
  tc::cotask<std::optional<TankerSecretProvisionalIdentity>>
  getProvisionalIdentityKeys(Unlock::Verification const& verification,
                             Crypto::SymmetricKey const& userSecret);
  tc::cotask<std::optional<TankerSecretProvisionalIdentity>>
  getVerifiedProvisionalIdentityKeys(Crypto::Hash const& hashedEmail);

  tc::cotask<nlohmann::json> emit(std::string const& event,
                                  nlohmann::json const& data);

  std::string connectionId() const;
  std::function<void()> blockAvailable;

private:
  std::unique_ptr<Network::AConnection> _cx;
  ConnectionHandler _connectionHandler;

  tc::task_auto_canceler _taskCanceler;
};
}
