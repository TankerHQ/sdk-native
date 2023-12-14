#pragma once

#include <Tanker/ProvisionalUsers/ProvisionalUserKeysStore.hpp>
#include <Tanker/ProvisionalUsers/SecretUser.hpp>
#include <Tanker/Trustchain/Actions/ProvisionalIdentityClaim.hpp>

#include <tconcurrent/coroutine.hpp>

#include <gsl/gsl-lite.hpp>

namespace Tanker::Users
{
class ILocalUserAccessor;
class IUserAccessor;
}

namespace Tanker::ProvisionalUsers::Updater
{

struct UsedSecretUser
{
  Crypto::PublicSignatureKey appSignaturePublicKey;
  Crypto::PublicSignatureKey tankerSignaturePublicKey;
  Crypto::EncryptionKeyPair appEncryptionKeyPair;
  Crypto::EncryptionKeyPair tankerEncryptionKeyPair;
};

tc::cotask<UsedSecretUser> extractKeysToStore(Users::ILocalUserAccessor& localUserAccessor,
                                              Trustchain::Actions::ProvisionalIdentityClaim const& action);

tc::cotask<std::vector<UsedSecretUser>> processClaimEntries(
    Users::ILocalUserAccessor& localUserAccessor,
    Users::IUserAccessor& contactAccessor,
    gsl::span<Trustchain::Actions::ProvisionalIdentityClaim const> actions);
}
