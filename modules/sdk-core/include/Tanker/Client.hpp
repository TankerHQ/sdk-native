#pragma once

#include <Tanker/Crypto/Hash.hpp>
#include <Tanker/Crypto/PublicSignatureKey.hpp>
#include <Tanker/EncryptedUserKey.hpp>
#include <Tanker/Identity/SecretPermanentIdentity.hpp>
#include <Tanker/Network/AConnection.hpp>
#include <Tanker/Trustchain/GroupId.hpp>
#include <Tanker/Trustchain/ResourceId.hpp>
#include <Tanker/Trustchain/TrustchainId.hpp>
#include <Tanker/Trustchain/UserId.hpp>
#include <Tanker/Types/TankerSecretProvisionalIdentity.hpp>
#include <Tanker/Unlock/Request.hpp>

#include <gsl-lite.hpp>
#include <nlohmann/json_fwd.hpp>
#include <tconcurrent/coroutine.hpp>
#include <tconcurrent/task_auto_canceler.hpp>

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <tuple>
#include <vector>

namespace Tanker
{

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
  void close();
  void setConnectionHandler(ConnectionHandler handler);
  tc::cotask<void> handleConnection();

  tc::cotask<void> pushBlock(gsl::span<uint8_t const> block);
  tc::cotask<void> pushKeys(gsl::span<std::vector<uint8_t> const> block);

  tc::cotask<void> createUser(
      Identity::SecretPermanentIdentity const& identity,
      gsl::span<uint8_t const> userCreation,
      gsl::span<uint8_t const> firstDevice,
      Unlock::Request const& verificationRequest,
      gsl::span<uint8_t const> encryptedVerificationKey);

  tc::cotask<void> setVerificationMethod(
      Trustchain::TrustchainId const& trustchainId,
      Trustchain::UserId const& userId,
      Unlock::Request const& verificationRequest);

  tc::cotask<std::vector<std::uint8_t>> fetchVerificationKey(
      Trustchain::TrustchainId const& trustchainId,
      Trustchain::UserId const& userId,
      Unlock::Request const& verificationRequest);

  tc::cotask<std::vector<Unlock::VerificationMethod>> fetchVerificationMethods(
      Trustchain::TrustchainId const& trustchainId,
      Trustchain::UserId const& userId);

  tc::cotask<EncryptedUserKey> getLastUserKey(
      Trustchain::TrustchainId const& trustchainId,
      Crypto::PublicSignatureKey const& devicePublicUserKey);

  tc::cotask<std::vector<std::string>> getBlocks(
      int index,
      std::vector<Trustchain::UserId> const& extra_users,
      std::vector<Trustchain::GroupId> const& extra_groups);

  tc::cotask<nlohmann::json> emit(std::string const& event,
                                  nlohmann::json const& data);

  std::string connectionId() const;

private:
  std::unique_ptr<Network::AConnection> _cx;
  ConnectionHandler _connectionHandler;

  tc::task_auto_canceler _taskCanceler;
};
}
