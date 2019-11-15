#include <Tanker/Preregistration.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/Errors/AssertionError.hpp>
#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Errors/Exception.hpp>
#include <Tanker/Groups/GroupUpdater.hpp>
#include <Tanker/Log/Log.hpp>
#include <Tanker/Trustchain/Actions/ProvisionalIdentityClaim.hpp>

TLOG_CATEGORY("Preregistration");

using Tanker::Trustchain::Actions::ProvisionalIdentityClaim;
using namespace Tanker::Errors;

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
  {
    throw Exception(make_error_code(Errc::InternalError),
                    "cannot find user key for claim decryption");
  }

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
