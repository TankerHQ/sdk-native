#include <Tanker/ProvisionalUsers/Manager.hpp>

#include <Tanker/AttachResult.hpp>
#include <Tanker/Errors/AppdErrc.hpp>
#include <Tanker/Errors/AssertionError.hpp>
#include <Tanker/Format/Enum.hpp>

#include <Tanker/Identity/Extract.hpp>
#include <Tanker/Log/Log.hpp>
#include <Tanker/ProvisionalUsers/IRequester.hpp>
#include <Tanker/ProvisionalUsers/ProvisionalUserKeysStore.hpp>
#include <Tanker/Unlock/Requester.hpp>
#include <Tanker/Users/EntryGenerator.hpp>
#include <Tanker/Users/LocalUser.hpp>
#include <Tanker/Users/LocalUserAccessor.hpp>

TLOG_CATEGORY(ProvisionalUsers);

namespace Tanker
{
namespace ProvisionalUsers
{
namespace
{
std::optional<Unlock::VerificationMethod> findVerificationMethod(
    gsl::span<Unlock::VerificationMethod const> methods, Email const& email)
{
  auto it = std::find_if(methods.begin(),
                         methods.end(),
                         [&email](Unlock::VerificationMethod const& method) {
                           if (auto const e = method.get_if<Email>())
                           {
                             return *e == email;
                           }
                           return false;
                         });
  if (it != methods.end())
    return *it;
  return std::nullopt;
}
}

Manager::Manager(Users::ILocalUserAccessor* localUserAccessor,
                 IRequester* requester,
                 Unlock::Requester* unlockRequester,
                 ProvisionalUsers::Accessor* provisionalUsersAccessor,
                 ProvisionalUserKeysStore* provisionalUserKeysStore,
                 Trustchain::TrustchainId const& trustchainId)
  : _localUserAccessor(localUserAccessor),
    _requester(requester),
    _unlockRequester(unlockRequester),
    _provisionalUsersAccessor(provisionalUsersAccessor),
    _provisionalUserKeysStore(provisionalUserKeysStore),
    _trustchainId(trustchainId)
{
}

tc::cotask<AttachResult> Manager::attachProvisionalIdentity(
    SSecretProvisionalIdentity const& sidentity,
    Crypto::SymmetricKey const& userSecret)
{
  auto const provisionalIdentity =
      Identity::extract<Identity::SecretProvisionalIdentity>(
          sidentity.string());

  if (provisionalIdentity.target != Identity::TargetType::Email)
  {
    throw Errors::AssertionError(
        fmt::format(FMT_STRING("unsupported provisional identity target {:s}"),
                    provisionalIdentity.target));
  }

  {
    auto optProvisionalKey =
        TC_AWAIT(_provisionalUserKeysStore
                     ->findProvisionalUserKeysByAppPublicEncryptionKey(
                         provisionalIdentity.appEncryptionKeyPair.publicKey));

    if (!optProvisionalKey)
    {
      TC_AWAIT(_provisionalUsersAccessor->refreshKeys());
      optProvisionalKey =
          TC_AWAIT(_provisionalUserKeysStore
                       ->findProvisionalUserKeysByAppPublicEncryptionKey(
                           provisionalIdentity.appEncryptionKeyPair.publicKey));
    }
    if (optProvisionalKey)
      TC_RETURN((AttachResult{Tanker::Status::Ready, std::nullopt}));
  }

  auto const email = Email{provisionalIdentity.value};
  try
  {
    auto verificationMethods =
        TC_AWAIT(_unlockRequester->fetchVerificationMethods(
            _localUserAccessor->get().userId()));
    Unlock::decryptMethods(verificationMethods, userSecret);

    if (findVerificationMethod(verificationMethods, email))
    {
      if (auto const tankerKeys =
              TC_AWAIT(_requester->getVerifiedProvisionalIdentityKeys()))
      {
        auto const localUser = TC_AWAIT(_localUserAccessor->pull());
        auto const claimAction = Users::createProvisionalIdentityClaimAction(
            _trustchainId,
            localUser.deviceId(),
            localUser.deviceKeys().signatureKeyPair.privateKey,
            localUser.userId(),
            ProvisionalUsers::SecretUser{
                provisionalIdentity.target,
                provisionalIdentity.value,
                provisionalIdentity.appEncryptionKeyPair,
                tankerKeys->encryptionKeyPair,
                provisionalIdentity.appSignatureKeyPair,
                tankerKeys->signatureKeyPair},
            localUser.currentKeyPair());
        TC_AWAIT(_requester->claimProvisionalIdentity(claimAction));
      }
      TC_RETURN((AttachResult{Tanker::Status::Ready, std::nullopt}));
    }
  }
  catch (Tanker::Errors::Exception const& e)
  {
    if (e.errorCode() != Errors::AppdErrc::VerificationNeeded)
      throw;
  }
  _provisionalIdentity = provisionalIdentity;
  TC_RETURN((AttachResult{Tanker::Status::IdentityVerificationNeeded, email}));
}

tc::cotask<void> Manager::verifyProvisionalIdentity(
    Unlock::Request const& unlockRequest)
{
  auto const tankerKeys =
      TC_AWAIT(_requester->getProvisionalIdentityKeys(unlockRequest));

  auto const localUser = TC_AWAIT(_localUserAccessor->pull());
  auto const clientEntry = Users::createProvisionalIdentityClaimAction(
      _trustchainId,
      localUser.deviceId(),
      localUser.deviceKeys().signatureKeyPair.privateKey,
      localUser.userId(),
      ProvisionalUsers::SecretUser{_provisionalIdentity->target,
                                   _provisionalIdentity->value,
                                   _provisionalIdentity->appEncryptionKeyPair,
                                   tankerKeys.encryptionKeyPair,
                                   _provisionalIdentity->appSignatureKeyPair,
                                   tankerKeys.signatureKeyPair},
      localUser.currentKeyPair());
  TC_AWAIT(_requester->claimProvisionalIdentity(clientEntry));

  _provisionalIdentity.reset();
  TC_AWAIT(_provisionalUsersAccessor->refreshKeys());
}

std::optional<Identity::SecretProvisionalIdentity> const&
Manager::provisionalIdentity() const
{
  return _provisionalIdentity;
}
}
}
