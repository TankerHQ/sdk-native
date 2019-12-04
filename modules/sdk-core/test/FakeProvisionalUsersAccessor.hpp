#include <Tanker/ProvisionalUsers/IAccessor.hpp>
#include <Tanker/ProvisionalUsers/ProvisionalUserKeysStore.hpp>

class FakeProvisionalUsersAccessor : public Tanker::ProvisionalUsers::IAccessor
{
public:
  FakeProvisionalUsersAccessor(Tanker::ProvisionalUserKeysStore const& store)
    : _store(store)
  {
  }

  tc::cotask<std::optional<Tanker::ProvisionalUserKeys>> pullEncryptionKeys(
      Tanker::Crypto::PublicSignatureKey const& appPublicSigKey,
      Tanker::Crypto::PublicSignatureKey const& tankerPublicSigKey) override
  {
    TC_RETURN(TC_AWAIT(
        _store.findProvisionalUserKeys(appPublicSigKey, tankerPublicSigKey)));
  }

  tc::cotask<std::optional<Tanker::ProvisionalUserKeys>>
  findEncryptionKeysFromCache(
      Tanker::Crypto::PublicSignatureKey const& appPublicSigKey,
      Tanker::Crypto::PublicSignatureKey const& tankerPublicSigKey) override
  {
    TC_RETURN(TC_AWAIT(
        _store.findProvisionalUserKeys(appPublicSigKey, tankerPublicSigKey)));
  }

  tc::cotask<void> refreshKeys() override
  {
    // do nothing
  }

private:
  Tanker::ProvisionalUserKeysStore const& _store;
};
