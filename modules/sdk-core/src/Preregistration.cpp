#include <Tanker/Preregistration.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Error.hpp>
#include <Tanker/Trustchain/Actions/ProvisionalIdentityClaim.hpp>

using Tanker::Trustchain::Actions::ProvisionalIdentityClaim;

namespace Tanker
{
namespace Preregistration
{
namespace
{
struct SecretProvisionalUserToStore
{
  Crypto::PublicSignatureKey appSignaturePublicKey;
  Crypto::PublicSignatureKey tankerSignaturePublicKey;
  Crypto::EncryptionKeyPair appEncryptionKeyPair;
  Crypto::EncryptionKeyPair tankerEncryptionKeyPair;
};

tc::cotask<SecretProvisionalUserToStore> extractKeysToStore(
    UserKeyStore& userKeyStore, Entry const& entry)
{
  auto const& provisionalIdentityClaim =
      entry.action.get<ProvisionalIdentityClaim>();

  auto const userKeyPair = TC_AWAIT(userKeyStore.findKeyPair(
      provisionalIdentityClaim.userPublicEncryptionKey()));

  if (!userKeyPair)
    throw Error::UserKeyNotFound("can't find user key for claim decryption");

  auto const provisionalIdentityKeys = Crypto::sealDecrypt(
      provisionalIdentityClaim.sealedPrivateEncryptionKeys(), *userKeyPair);

  // this size is ensured because the encrypted buffer has a fixed size
  assert(provisionalIdentityKeys.size() ==
         2 * Crypto::PrivateEncryptionKey::arraySize);

  auto const appEncryptionKeyPair =
      Crypto::makeEncryptionKeyPair(Crypto::PrivateEncryptionKey(
          gsl::make_span(provisionalIdentityKeys)
              .subspan(0, Crypto::PrivateEncryptionKey::arraySize)));
  auto const tankerEncryptionKeyPair =
      Crypto::makeEncryptionKeyPair(Crypto::PrivateEncryptionKey(
          gsl::make_span(provisionalIdentityKeys)
              .subspan(Crypto::PrivateEncryptionKey::arraySize)));

  TC_RETURN((SecretProvisionalUserToStore{
      provisionalIdentityClaim.appSignaturePublicKey(),
      provisionalIdentityClaim.tankerSignaturePublicKey(),
      appEncryptionKeyPair,
      tankerEncryptionKeyPair}));
}
}

tc::cotask<void> applyEntry(UserKeyStore& userKeyStore,
                            ProvisionalUserKeysStore& provisionalUserKeysStore,
                            Entry const& entry)
{
  auto const toStore = TC_AWAIT(extractKeysToStore(userKeyStore, entry));

  TC_AWAIT(provisionalUserKeysStore.putProvisionalUserKeys(
      toStore.appSignaturePublicKey,
      toStore.tankerSignaturePublicKey,
      {toStore.appEncryptionKeyPair, toStore.tankerEncryptionKeyPair}));
}
}
}
