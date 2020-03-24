#pragma once

#include <Tanker/AttachResult.hpp>
#include <Tanker/EncryptionSession.hpp>
#include <Tanker/Network/SdkInfo.hpp>
#include <Tanker/Session.hpp>
#include <Tanker/Status.hpp>
#include <Tanker/Streams/DecryptionStreamAdapter.hpp>
#include <Tanker/Streams/EncryptionStream.hpp>
#include <Tanker/Streams/InputSource.hpp>
#include <Tanker/Trustchain/DeviceId.hpp>
#include <Tanker/Types/Passphrase.hpp>
#include <Tanker/Types/SGroupId.hpp>
#include <Tanker/Types/SPublicIdentity.hpp>
#include <Tanker/Types/SResourceId.hpp>
#include <Tanker/Types/SSecretProvisionalIdentity.hpp>
#include <Tanker/Types/SUserId.hpp>
#include <Tanker/Types/VerificationCode.hpp>
#include <Tanker/Types/VerificationKey.hpp>
#include <Tanker/Unlock/Verification.hpp>
#include <Tanker/Users/Device.hpp>

#include <boost/variant2/variant.hpp>
#include <gsl-lite.hpp>
#include <tconcurrent/coroutine.hpp>
#include <tconcurrent/task_auto_canceler.hpp>

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace Tanker
{
class Core
{
public:
  using SessionClosedHandler = std::function<void()>;

  ~Core();
  Core(std::string url, Network::SdkInfo infos, std::string writablePath);
  Tanker::Status status() const;

  tc::cotask<Status> start(std::string const& identity);

  tc::cotask<void> registerIdentity(Unlock::Verification const& verification);
  tc::cotask<void> verifyIdentity(Unlock::Verification const& verification);
  void stop();

  tc::cotask<void> encrypt(
      uint8_t* encryptedData,
      gsl::span<uint8_t const> clearData,
      std::vector<SPublicIdentity> const& publicIdentities = {},
      std::vector<SGroupId> const& groupIds = {});

  tc::cotask<std::vector<uint8_t>> encrypt(
      gsl::span<uint8_t const> clearData,
      std::vector<SPublicIdentity> const& publicIdentities = {},
      std::vector<SGroupId> const& groupIds = {});

  tc::cotask<void> decrypt(uint8_t* decryptedData,
                           gsl::span<uint8_t const> encryptedData);

  tc::cotask<std::vector<uint8_t>> decrypt(
      gsl::span<uint8_t const> encryptedData);

  tc::cotask<void> share(std::vector<SResourceId> const& resourceId,
                         std::vector<SPublicIdentity> const& publicIdentities,
                         std::vector<SGroupId> const& groupIds);

  tc::cotask<SGroupId> createGroup(std::vector<SPublicIdentity> const& members);
  tc::cotask<void> updateGroupMembers(
      SGroupId const& groupId, std::vector<SPublicIdentity> const& usersToAdd);

  tc::cotask<VerificationKey> generateVerificationKey();

  tc::cotask<void> setVerificationMethod(Unlock::Verification const& method);
  tc::cotask<std::vector<Unlock::VerificationMethod>> getVerificationMethods();

  tc::cotask<AttachResult> attachProvisionalIdentity(
      SSecretProvisionalIdentity const& sidentity);
  tc::cotask<void> verifyProvisionalIdentity(
      Unlock::Verification const& verification);

  Trustchain::DeviceId const& deviceId() const;
  tc::cotask<std::vector<Users::Device>> getDeviceList() const;

  tc::cotask<void> revokeDevice(Trustchain::DeviceId const& deviceId);

  tc::cotask<Streams::EncryptionStream> makeEncryptionStream(
      Streams::InputSource,
      std::vector<SPublicIdentity> const& suserIds = {},
      std::vector<SGroupId> const& sgroupIds = {});

  tc::cotask<Streams::DecryptionStreamAdapter> makeDecryptionStream(
      Streams::InputSource);

  tc::cotask<EncryptionSession> makeEncryptionSession(
      std::vector<SPublicIdentity> const& publicIdentities,
      std::vector<SGroupId> const& groupIds);

  void setSessionClosedHandler(SessionClosedHandler);

  static Trustchain::ResourceId getResourceId(
      gsl::span<uint8_t const> encryptedData);

  tc::cotask<void> nukeDatabase();

private:
  std::string _url;
  Network::SdkInfo _info;
  std::string _writablePath;
  std::unique_ptr<class Session> _session;

  SessionClosedHandler _sessionClosed;

  void reset();
  void assertStatus(Status wanted, std::string const& string) const;

  template <typename F>
  decltype(std::declval<F>()()) resetOnFailure(F&& f);

  tc::cotask<Status> startImpl(std::string const& identity);
};
}
