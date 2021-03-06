#pragma once

#include <Tanker/AttachResult.hpp>
#include <Tanker/EncryptionSession.hpp>
#include <Tanker/Network/HttpClient.hpp>
#include <Tanker/ResourceKeys/Store.hpp>
#include <Tanker/SdkInfo.hpp>
#include <Tanker/Streams/DecryptionStreamAdapter.hpp>
#include <Tanker/Streams/EncryptionStream.hpp>
#include <Tanker/Streams/InputSource.hpp>
#include <Tanker/Trustchain/DeviceId.hpp>
#include <Tanker/Types/SGroupId.hpp>
#include <Tanker/Types/SPublicIdentity.hpp>
#include <Tanker/Types/SResourceId.hpp>
#include <Tanker/Types/SSecretProvisionalIdentity.hpp>
#include <Tanker/Types/VerificationKey.hpp>
#include <Tanker/Unlock/Verification.hpp>
#include <Tanker/Users/Device.hpp>

#include <gsl/gsl-lite.hpp>
#include <tconcurrent/coroutine.hpp>

#include <memory>
#include <string>
#include <vector>

namespace Tanker
{
class Session;

class Core
{
public:
  enum class ShareWithSelf : bool
  {
    No,
    Yes,
  };

  enum class VerifyWithToken : bool
  {
    No,
    Yes,
  };

  // There are hidden casts of this enum, so grep them if you change the enum
  static_assert(static_cast<int>(ShareWithSelf::No) == 0);
  static_assert(static_cast<int>(ShareWithSelf::Yes) == 1);

  using SessionClosedHandler = std::function<void()>;

  Core(std::string url,
       SdkInfo info,
       std::string writablePath,
       std::unique_ptr<Network::Backend> backend);
  ~Core();

  tc::cotask<Status> start(std::string const& identity);
  tc::cotask<std::optional<std::string>> registerIdentity(
      Unlock::Verification const& verification, VerifyWithToken withToken);
  tc::cotask<std::optional<std::string>> verifyIdentity(
      Unlock::Verification const& verification, VerifyWithToken withToken);

  tc::cotask<void> encrypt(
      uint8_t* encryptedData,
      gsl::span<uint8_t const> clearData,
      std::vector<SPublicIdentity> const& spublicIdentities,
      std::vector<SGroupId> const& sgroupIds,
      ShareWithSelf shareWithSelf);

  tc::cotask<std::vector<uint8_t>> encrypt(
      gsl::span<uint8_t const> clearData,
      std::vector<SPublicIdentity> const& spublicIdentities,
      std::vector<SGroupId> const& sgroupIds,
      ShareWithSelf shareWithSelf);

  tc::cotask<void> decrypt(uint8_t* decryptedData,
                           gsl::span<uint8_t const> encryptedData);

  tc::cotask<std::vector<uint8_t>> decrypt(
      gsl::span<uint8_t const> encryptedData);

  tc::cotask<void> share(std::vector<SResourceId> const& sresourceIds,
                         std::vector<SPublicIdentity> const& publicIdentities,
                         std::vector<SGroupId> const& groupIds);

  tc::cotask<SGroupId> createGroup(
      std::vector<SPublicIdentity> const& spublicIdentities);
  tc::cotask<void> updateGroupMembers(
      SGroupId const& groupIdString,
      std::vector<SPublicIdentity> const& spublicIdentitiesToAdd);

  tc::cotask<std::optional<std::string>> setVerificationMethod(
      Unlock::Verification const& method, VerifyWithToken withToken);
  tc::cotask<std::vector<Unlock::VerificationMethod>> getVerificationMethods();
  tc::cotask<VerificationKey> generateVerificationKey() const;

  tc::cotask<AttachResult> attachProvisionalIdentity(
      SSecretProvisionalIdentity const& sidentity);
  tc::cotask<void> verifyProvisionalIdentity(
      Unlock::Verification const& verification);

  tc::cotask<void> revokeDevice(Trustchain::DeviceId const& deviceId);

  Trustchain::DeviceId const& deviceId() const;
  tc::cotask<std::vector<Users::Device>> getDeviceList() const;

  tc::cotask<Streams::EncryptionStream> makeEncryptionStream(
      Streams::InputSource,
      std::vector<SPublicIdentity> const& suserIds,
      std::vector<SGroupId> const& sgroupIds,
      ShareWithSelf shareWithSelf);

  tc::cotask<Streams::DecryptionStreamAdapter> makeDecryptionStream(
      Streams::InputSource);

  tc::cotask<EncryptionSession> makeEncryptionSession(
      std::vector<SPublicIdentity> const& spublicIdentities,
      std::vector<SGroupId> const& sgroupIds,
      ShareWithSelf shareWithSelf);

  Status status() const;

  static Trustchain::ResourceId getResourceId(
      gsl::span<uint8_t const> encryptedData);

  tc::cotask<void> stop();
  tc::cotask<void> quickStop();
  tc::cotask<void> nukeDatabase();
  void setSessionClosedHandler(SessionClosedHandler);

  void setHttpSessionToken(std::string_view);

  tc::cotask<void> confirmRevocation();

private:
  tc::cotask<Status> startImpl(std::string const& b64Identity);
  tc::cotask<void> registerIdentityImpl(
      Unlock::Verification const& verification,
      std::optional<std::string> const& withTokenNonce);
  tc::cotask<void> verifyIdentityImpl(
      Unlock::Verification const& verification,
      std::optional<std::string> const& withTokenNonce);

  tc::cotask<VerificationKey> fetchVerificationKey(
      Unlock::Verification const& verification,
      std::optional<std::string> const& withTokenNonce);
  tc::cotask<VerificationKey> getVerificationKey(
      Unlock::Verification const& verification,
      std::optional<std::string> const& withTokenNonce);
  tc::cotask<Crypto::SymmetricKey> getResourceKey(
      Trustchain::ResourceId const&);

  std::optional<std::string> makeWithTokenRandomNonce(VerifyWithToken wanted);
  tc::cotask<std::string> getSessionToken(
      Unlock::Verification const& verification,
      std::string const& withTokenNonce);

  void assertStatus(Status wanted, std::string const& string) const;
  void assertStatus(std::initializer_list<Status> wanted,
                    std::string const& action) const;
  void reset();
  template <typename F>
  decltype(std::declval<F>()()) resetOnFailure(
      F&& f, std::vector<Errors::Errc> const& additionalErrorsToIgnore = {});

private:
  std::string _url;
  std::string _instanceId;
  SdkInfo _info;
  std::string _writablePath;
  SessionClosedHandler _sessionClosed;
  std::unique_ptr<Network::Backend> _backend;
  std::shared_ptr<Session> _session;
};
}
