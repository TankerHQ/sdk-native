#pragma once

#include <Tanker/AConnection.hpp>
#include <Tanker/Crypto/EncryptionKeyPair.hpp>
#include <Tanker/Crypto/Hash.hpp>
#include <Tanker/Crypto/PublicSignatureKey.hpp>
#include <Tanker/Crypto/Signature.hpp>
#include <Tanker/Crypto/SignatureKeyPair.hpp>
#include <Tanker/EncryptedUserKey.hpp>
#include <Tanker/Trustchain/DeviceId.hpp>
#include <Tanker/Trustchain/GroupId.hpp>
#include <Tanker/Trustchain/TrustchainId.hpp>
#include <Tanker/Trustchain/UserId.hpp>
#include <Tanker/Types/Email.hpp>
#include <Tanker/Types/TankerSecretProvisionalIdentity.hpp>
#include <Tanker/Types/VerificationCode.hpp>
#include <Tanker/Unlock/Methods.hpp>

#include <boost/signals2/signal.hpp>
#include <gsl-lite.hpp>
#include <mpark/variant.hpp>
#include <nlohmann/json_fwd.hpp>
#include <tconcurrent/coroutine.hpp>
#include <tconcurrent/task_auto_canceler.hpp>

#include <optional.hpp>

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace Tanker
{
namespace Unlock
{
struct FetchAnswer;
struct Message;
struct Request;
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

  Client(std::unique_ptr<AConnection> conn,
         ConnectionHandler connectionHandler = {});

  void start();
  void setConnectionHandler(ConnectionHandler handler);
  tc::cotask<void> handleConnection();

  tc::cotask<void> pushBlock(gsl::span<uint8_t const> block);
  tc::cotask<void> pushKeys(gsl::span<std::vector<uint8_t> const> block);

  tc::cotask<UserStatusResult> userStatus(
      Trustchain::TrustchainId const& trustchainId,
      Trustchain::UserId const& userId,
      Crypto::PublicSignatureKey const& publicSignatureKey);

  tc::cotask<void> createVerificationKey(Unlock::Message const& request);
  tc::cotask<void> updateVerificationKey(Unlock::Message const& request);
  tc::cotask<Unlock::FetchAnswer> fetchVerificationKey(Unlock::Request const& req);

  tc::cotask<std::string> requestAuthChallenge();
  tc::cotask<Unlock::Methods> authenticateDevice(nlohmann::json const& request);
  tc::cotask<EncryptedUserKey> getLastUserKey(
      Trustchain::TrustchainId const& trustchainId,
      Trustchain::DeviceId const& deviceId);
  tc::cotask<void> subscribeToCreation(
      Trustchain::TrustchainId const& trustchainId,
      Crypto::PublicSignatureKey const& publicKey,
      Crypto::Signature const& signedPublicKey);

  tc::cotask<std::vector<std::string>> getBlocks(
      int index,
      std::vector<Trustchain::UserId> const& extra_users,
      std::vector<Trustchain::GroupId> const& extra_groups);
  tc::cotask<std::vector<
      std::pair<Crypto::PublicSignatureKey, Crypto::PublicEncryptionKey>>>
  getPublicProvisionalIdentities(gsl::span<Email const>);
  tc::cotask<nonstd::optional<TankerSecretProvisionalIdentity>>
  getProvisionalIdentityKeys(Email const& provisionalIdentity,
                             VerificationCode const& verificationCode);

  std::string connectionId() const;
  boost::signals2::signal<void()> blockAvailable;
  boost::signals2::signal<void()> deviceCreated;

private:
  std::unique_ptr<AConnection> _cx;
  ConnectionHandler _connectionHandler;

  tc::task_auto_canceler _taskCanceler;

  tc::cotask<nlohmann::json> emit(std::string const& event,
                                  nlohmann::json const& data);
};
}
