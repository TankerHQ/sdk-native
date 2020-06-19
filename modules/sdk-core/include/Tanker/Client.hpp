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

#include <gsl/gsl-lite.hpp>
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

  using ConnectionHandler = std::function<void()>;

  Client(Network::ConnectionPtr conn, ConnectionHandler connectionHandler = {});

  void start();
  void close();
  void setConnectionHandler(ConnectionHandler handler);
  void handleConnection();

  tc::cotask<EncryptedUserKey> getLastUserKey(
      Trustchain::TrustchainId const& trustchainId,
      Crypto::PublicSignatureKey const& devicePublicUserKey);

  tc::cotask<nlohmann::json> emit(std::string const& event,
                                  nlohmann::json const& data);

  std::string connectionId() const;

private:
  std::unique_ptr<Network::AConnection> _cx;
  ConnectionHandler _connectionHandler;

  tc::task_auto_canceler _taskCanceler;
};
}
