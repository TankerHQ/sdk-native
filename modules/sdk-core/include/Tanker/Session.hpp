#pragma once

#include <Tanker/AttachResult.hpp>
#include <Tanker/Client.hpp>
#include <Tanker/DataStore/ADatabase.hpp>
#include <Tanker/EncryptionSession.hpp>
#include <Tanker/Groups/Accessor.hpp>
#include <Tanker/Groups/Store.hpp>
#include <Tanker/Identity/PublicIdentity.hpp>
#include <Tanker/Identity/SecretProvisionalIdentity.hpp>
#include <Tanker/Network/SdkInfo.hpp>
#include <Tanker/ProvisionalUsers/Accessor.hpp>
#include <Tanker/ProvisionalUsers/IRequester.hpp>
#include <Tanker/ProvisionalUsers/Manager.hpp>
#include <Tanker/ProvisionalUsers/ProvisionalUserKeysStore.hpp>
#include <Tanker/ResourceKeyAccessor.hpp>
#include <Tanker/ResourceKeyStore.hpp>
#include <Tanker/Streams/DecryptionStreamAdapter.hpp>
#include <Tanker/Streams/EncryptionStream.hpp>
#include <Tanker/Streams/InputSource.hpp>
#include <Tanker/Trustchain/Actions/DeviceCreation.hpp>
#include <Tanker/Trustchain/Context.hpp>
#include <Tanker/Trustchain/DeviceId.hpp>
#include <Tanker/Trustchain/GroupId.hpp>
#include <Tanker/Trustchain/TrustchainId.hpp>
#include <Tanker/Trustchain/UserId.hpp>
#include <Tanker/Types/Email.hpp>
#include <Tanker/Types/Passphrase.hpp>
#include <Tanker/Types/SGroupId.hpp>
#include <Tanker/Types/SPublicIdentity.hpp>
#include <Tanker/Types/SResourceId.hpp>
#include <Tanker/Types/SSecretProvisionalIdentity.hpp>
#include <Tanker/Types/VerificationKey.hpp>
#include <Tanker/Unlock/Methods.hpp>
#include <Tanker/Unlock/Verification.hpp>
#include <Tanker/Users/Device.hpp>
#include <Tanker/Users/LocalUserAccessor.hpp>
#include <Tanker/Users/UserAccessor.hpp>

#include <gsl-lite.hpp>
#include <tconcurrent/coroutine.hpp>
#include <tconcurrent/future.hpp>
#include <tconcurrent/promise.hpp>
#include <tconcurrent/task_auto_canceler.hpp>

#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <vector>

namespace Tanker
{
struct Entry;
struct UnverifiedEntry;

namespace Groups
{
class IRequester;
}

namespace Users
{
class IRequester;
}

class Session
{
public:
  struct Storage
  {
    Storage(DataStore::DatabasePtr& db,
            Users::IRequester* userRequester,
            Groups::IRequester* groupsRequester,
            ProvisionalUsers::IRequester* provisionalRequester,
            std::unique_ptr<Users::LocalUserAccessor> plocalUserAccessor);

    Groups::Store groupStore;
    ResourceKeyStore resourceKeyStore;
    ProvisionalUserKeysStore provisionalUserKeysStore;

    std::unique_ptr<Users::LocalUserAccessor> localUserAccessor;
    mutable Users::UserAccessor userAccessor;
    ProvisionalUsers::Accessor provisionalUsersAccessor;
    ProvisionalUsers::Manager provisionalUsersManager;
    Groups::Accessor groupAccessor;
    ResourceKeyAccessor resourceKeyAccessor;
  };

  using DeviceRevokedHandler = std::function<void()>;

  ~Session();
  Session(std::string url, Network::SdkInfo info);

  tc::cotask<Status> open(Identity::SecretPermanentIdentity const& identity,
                          std::string const& writablePath);
  tc::cotask<void> createDevice(Unlock::Verification const& verification);
  tc::cotask<void> createUser(Unlock::Verification const& verification);

  tc::cotask<void> encrypt(uint8_t* encryptedData,
                           gsl::span<uint8_t const> clearData,
                           std::vector<SPublicIdentity> const& suserIds = {},
                           std::vector<SGroupId> const& sgroupIds = {});

  tc::cotask<std::vector<uint8_t>> encrypt(
      gsl::span<uint8_t const> clearData,
      std::vector<SPublicIdentity> const& suserIds = {},
      std::vector<SGroupId> const& sgroupIds = {});

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

  tc::cotask<void> setVerificationMethod(Unlock::Verification const& method);
  tc::cotask<std::vector<Unlock::VerificationMethod>>
  fetchVerificationMethods();
  tc::cotask<VerificationKey> fetchVerificationKey(
      Unlock::Verification const& verification);
  tc::cotask<VerificationKey> getVerificationKey(Unlock::Verification const&);
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
      std::vector<SPublicIdentity> const& suserIds = {},
      std::vector<SGroupId> const& sgroupIds = {});

  tc::cotask<Streams::DecryptionStreamAdapter> makeDecryptionStream(
      Streams::InputSource);

  tc::cotask<EncryptionSession> makeEncryptionSession(
      std::vector<SPublicIdentity> const& spublicIdentities,
      std::vector<SGroupId> const& sgroupIds);

  inline Status status() const
  {
    return _status;
  }

  tc::cotask<void> nukeDatabase();

private:
  Trustchain::UserId const& userId() const;
  Trustchain::TrustchainId const& trustchainId() const;
  Crypto::SymmetricKey const& userSecret() const;
  tc::cotask<Crypto::SymmetricKey> getResourceKey(
      Trustchain::ResourceId const&);
  tc::cotask<void> finalizeSessionOpening(
      std::unique_ptr<Users::LocalUserStore> localUserStore);

private:
  std::unique_ptr<Client> _client;
  std::unique_ptr<Users::IRequester> _userRequester;
  std::unique_ptr<Groups::IRequester> _groupsRequester;
  std::unique_ptr<ProvisionalUsers::IRequester> _provisionalRequester;
  DataStore::DatabasePtr _db;
  std::optional<Identity::SecretPermanentIdentity> _identity;
  Status _status;
  std::unique_ptr<Storage> _storage;
};
}
