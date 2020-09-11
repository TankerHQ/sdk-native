#pragma once

#include <Tanker/Trustchain/Context.hpp>
#include <Tanker/Trustchain/UserId.hpp>
#include <Tanker/Users/ILocalUserAccessor.hpp>
#include <Tanker/Users/LocalUser.hpp>

#include <tconcurrent/coroutine.hpp>

#include <memory>
#include <tuple>

namespace Tanker
{
struct DeviceKeys;
}

namespace Tanker::Users
{
class ContactStore;
class IRequester;
class LocalUserStore;

class LocalUserAccessor : public ILocalUserAccessor
{
  LocalUserAccessor() = delete;
  LocalUserAccessor(LocalUserAccessor const&) = delete;
  LocalUserAccessor& operator=(LocalUserAccessor const&) = delete;
  LocalUserAccessor& operator=(LocalUserAccessor&&) = delete;

public:
  LocalUserAccessor(LocalUserAccessor&&) = default;

  static tc::cotask<LocalUserAccessor> create(
      Trustchain::UserId const& userId,
      Trustchain::TrustchainId const& trustchainId,
      IRequester* requester,
      LocalUserStore* store);

  LocalUserAccessor(LocalUser localUser,
                    Trustchain::Context context,
                    IRequester* requester,
                    LocalUserStore* localUserStore);

  ~LocalUserAccessor() override;

  tc::cotask<LocalUser const&> pull() override;

  LocalUser const& get() const override;
  Trustchain::Context const& getContext() const;

  tc::cotask<std::optional<Crypto::EncryptionKeyPair>> pullUserKeyPair(
      Crypto::PublicEncryptionKey const& publicUserKey) override;

  tc::cotask<void> confirmRevocation();

private:
  tc::cotask<void> update();

  LocalUser _localUser;
  Trustchain::Context _context;
  IRequester* _requester;
  LocalUserStore* _store;
};
}
