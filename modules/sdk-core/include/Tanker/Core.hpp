#pragma once

#include <Tanker/AttachResult.hpp>
#include <Tanker/Crypto/Padding.hpp>
#include <Tanker/DataStore/Backend.hpp>
#include <Tanker/EncryptionSession.hpp>
#include <Tanker/Network/HttpClient.hpp>
#include <Tanker/Oidc/NonceManager.hpp>
#include <Tanker/ResourceKeys/Store.hpp>
#include <Tanker/SdkInfo.hpp>
#include <Tanker/Streams/InputSource.hpp>
#include <Tanker/Trustchain/DeviceId.hpp>
#include <Tanker/Types/OidcNonce.hpp>
#include <Tanker/Types/SGroupId.hpp>
#include <Tanker/Types/SPublicIdentity.hpp>
#include <Tanker/Types/SResourceId.hpp>
#include <Tanker/Types/SSecretProvisionalIdentity.hpp>
#include <Tanker/Types/VerificationKey.hpp>
#include <Tanker/Users/Device.hpp>
#include <Tanker/Verification/Verification.hpp>

#include <gsl/gsl-lite.hpp>
#include <tconcurrent/coroutine.hpp>

#include <memory>
#include <optional>
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

  enum class AllowE2eMethodSwitch : bool
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
       std::string dataPath,
       std::string cachePath,
       std::unique_ptr<Network::Backend> networkBackend,
       std::unique_ptr<DataStore::Backend> datastoreBackend);
  ~Core();

  tc::cotask<Status> start(std::string const& identity);
  tc::cotask<void> enrollUser(
      std::string const& identity,
      std::vector<Verification::Verification> const& verifications);
  tc::cotask<std::optional<std::string>> registerIdentity(
      Verification::Verification const& verification,
      VerifyWithToken withToken);
  tc::cotask<std::optional<std::string>> verifyIdentity(
      Verification::Verification const& verification,
      VerifyWithToken withToken);

  tc::cotask<Oidc::Nonce> createOidcNonce();
  void setOidcTestNonce(Oidc::Nonce const& nonce);

  tc::cotask<void> encrypt(
      gsl::span<uint8_t> encryptedData,
      gsl::span<uint8_t const> clearData,
      std::vector<SPublicIdentity> const& spublicIdentities,
      std::vector<SGroupId> const& sgroupIds,
      ShareWithSelf shareWithSelf,
      std::optional<uint32_t> paddingStep);

  tc::cotask<std::vector<uint8_t>> encrypt(
      gsl::span<uint8_t const> clearData,
      std::vector<SPublicIdentity> const& spublicIdentities,
      std::vector<SGroupId> const& sgroupIds,
      ShareWithSelf shareWithSelf,
      std::optional<uint32_t> paddingStep);

  tc::cotask<uint64_t> decrypt(gsl::span<uint8_t> decryptedData,
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
      std::vector<SPublicIdentity> const& spublicIdentitiesToAdd,
      std::vector<SPublicIdentity> const& spublicIdentitiesToRemove);

  tc::cotask<std::optional<std::string>> setVerificationMethod(
      Verification::Verification const& method,
      VerifyWithToken withToken,
      AllowE2eMethodSwitch allowE2eSwitch);
  tc::cotask<std::vector<Verification::VerificationMethod>>
  getVerificationMethods();
  tc::cotask<VerificationKey> generateVerificationKey() const;

  tc::cotask<AttachResult> attachProvisionalIdentity(
      SSecretProvisionalIdentity const& sidentity);
  tc::cotask<void> verifyProvisionalIdentity(
      Verification::Verification const& verification);

  Trustchain::DeviceId const& deviceId() const;
  tc::cotask<std::vector<Users::Device>> getDeviceList() const;

  tc::cotask<std::tuple<Streams::InputSource, Trustchain::ResourceId>>
  makeEncryptionStream(Streams::InputSource,
                       std::vector<SPublicIdentity> const& suserIds,
                       std::vector<SGroupId> const& sgroupIds,
                       ShareWithSelf shareWithSelf,
                       std::optional<uint32_t> paddingStep);

  tc::cotask<std::tuple<Streams::InputSource, Trustchain::ResourceId>>
      makeDecryptionStream(Streams::InputSource);

  tc::cotask<EncryptionSession> makeEncryptionSession(
      std::vector<SPublicIdentity> const& spublicIdentities,
      std::vector<SGroupId> const& sgroupIds,
      ShareWithSelf shareWithSelf,
      std::optional<uint32_t> paddingStep);

  Status status() const;

  static Trustchain::ResourceId getResourceId(
      gsl::span<uint8_t const> encryptedData);

  tc::cotask<void> stop();
  void quickStop();
  void nukeDatabase();
  void setSessionClosedHandler(SessionClosedHandler);

  void setHttpSessionToken(std::string_view);

  tc::cotask<void> confirmRevocation();

private:
  tc::cotask<Status> startImpl(std::string const& b64Identity);
  tc::cotask<void> registerIdentityImpl(
      Verification::Verification const& verification,
      std::optional<std::string> const& withTokenNonce);
  tc::cotask<void> verifyIdentityImpl(
      Verification::Verification const& verification,
      std::optional<std::string> const& withTokenNonce);

  tc::cotask<VerificationKey> fetchVerificationKey(
      Verification::Verification const& verification,
      std::optional<std::string> const& withTokenNonce);
  tc::cotask<VerificationKey> fetchE2eVerificationKey(
      Verification::Verification const& verification,
      Crypto::SymmetricKey const& e2eEncryptionKey,
      std::optional<std::string> const& withTokenNonce);
  tc::cotask<VerificationKey> getVerificationKey(
      Verification::Verification const& verification,
      std::optional<std::string> const& withTokenNonce);
  tc::cotask<Crypto::SymmetricKey> getResourceKey(
      Trustchain::ResourceId const&);

  std::optional<std::string> makeWithTokenRandomNonce(VerifyWithToken wanted);
  tc::cotask<std::string> getSessionToken(
      Verification::Verification const& verification,
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
  std::string _dataPath;
  std::string _cachePath;
  SessionClosedHandler _sessionClosed;
  std::unique_ptr<Network::Backend> _networkBackend;
  std::unique_ptr<DataStore::Backend> _datastoreBackend;
  std::shared_ptr<Session> _session;
  std::shared_ptr<Oidc::NonceManager> _oidcManager;
};
}
