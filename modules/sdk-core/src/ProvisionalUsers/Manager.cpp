#include <Tanker/ProvisionalUsers/Manager.hpp>

#include <Tanker/AttachResult.hpp>
#include <Tanker/Errors/AppdErrc.hpp>
#include <Tanker/Errors/AssertionError.hpp>
#include <Tanker/Format/Enum.hpp>

#include <Tanker/Identity/Extract.hpp>
#include <Tanker/Log/Log.hpp>
#include <Tanker/ProvisionalUsers/IRequester.hpp>
#include <Tanker/ProvisionalUsers/ProvisionalUserKeysStore.hpp>
#include <Tanker/Users/EntryGenerator.hpp>
#include <Tanker/Users/LocalUser.hpp>
#include <Tanker/Users/LocalUserAccessor.hpp>
#include <Tanker/Verification/Requester.hpp>

TLOG_CATEGORY(ProvisionalUsers);

namespace Tanker
{
namespace ProvisionalUsers
{
namespace
{
std::optional<Verification::VerificationMethod> findVerificationMethod(
    gsl::span<Verification::VerificationMethod const> methods,
    Verification::VerificationMethod const& wanted)
{
  auto it = std::find(methods.begin(), methods.end(), wanted);
  if (it != methods.end())
    return *it;
  return std::nullopt;
}

Verification::VerificationMethod getSecretProvisionalVerifMethod(
    Identity::SecretProvisionalIdentity const& provisionalIdentity)
{
  if (provisionalIdentity.target == Identity::TargetType::Email)
    return Email{provisionalIdentity.value};
  else if (provisionalIdentity.target == Identity::TargetType::PhoneNumber)
    return PhoneNumber{provisionalIdentity.value};
  else
    throw Errors::AssertionError(
        "Unexpected target for secret provisional identity");
}
}

Manager::Manager(Users::ILocalUserAccessor* localUserAccessor,
                 IRequester* requester,
                 Verification::Requester* unlockRequester,
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

tc::cotask<std::optional<ProvisionalUserKeys>> Manager::fetchProvisionalKeys(
    Identity::SecretProvisionalIdentity const& provisionalIdentity)
{
  auto optProvisionalKey = TC_AWAIT(
      _provisionalUserKeysStore->findProvisionalUserKeysByAppPublicSignatureKey(
          provisionalIdentity.appSignatureKeyPair.publicKey));

  if (!optProvisionalKey)
  {
    TC_AWAIT(_provisionalUsersAccessor->refreshKeys());
    optProvisionalKey =
        TC_AWAIT(_provisionalUserKeysStore
                     ->findProvisionalUserKeysByAppPublicSignatureKey(
                         provisionalIdentity.appSignatureKeyPair.publicKey));
  }
  TC_RETURN(std::move(optProvisionalKey));
}

tc::cotask<AttachResult> Manager::claimProvisionalIdentityWithMethod(
    Identity::SecretProvisionalIdentity const& provisionalIdentity,
    Verification::VerificationMethod const& method,
    Crypto::SymmetricKey const& userSecret)
{
  auto const request =
      Verification::makeRequestWithSession(provisionalIdentity, userSecret);
  if (auto const tankerKeys =
          TC_AWAIT(_requester->getVerifiedProvisionalIdentityKeys(
              _localUserAccessor->get().userId(), request)))
  {
    auto const localUser = TC_AWAIT(_localUserAccessor->pull());
    auto const claimAction = Users::createProvisionalIdentityClaimAction(
        _trustchainId,
        localUser.deviceId(),
        localUser.deviceKeys().signatureKeyPair.privateKey,
        localUser.userId(),
        ProvisionalUsers::SecretUser{provisionalIdentity.target,
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

tc::cotask<AttachResult> Manager::claimProvisionalIdentity(
    Identity::SecretProvisionalIdentity const& provisionalIdentity,
    Crypto::SymmetricKey const& userSecret)
{
  auto method = getSecretProvisionalVerifMethod(provisionalIdentity);
  try
  {
    auto const& userId = _localUserAccessor->get().userId();
    auto genericVerificationMethods =
        TC_AWAIT(_unlockRequester->fetchVerificationMethods(userId));
    auto verificationMethods = TC_AWAIT(
        Verification::decryptMethods(genericVerificationMethods, userSecret));

    if (findVerificationMethod(verificationMethods, method))
    {
      TC_RETURN(TC_AWAIT(claimProvisionalIdentityWithMethod(
          provisionalIdentity, method, userSecret)));
    }
  }
  catch (Tanker::Errors::Exception const& e)
  {
    if (e.errorCode() != Errors::AppdErrc::VerificationNeeded)
      throw;
  }
  _provisionalIdentity = provisionalIdentity;
  TC_RETURN((AttachResult{Tanker::Status::IdentityVerificationNeeded, method}));
}

tc::cotask<AttachResult> Manager::attachProvisionalIdentity(
    SSecretProvisionalIdentity const& sidentity,
    Crypto::SymmetricKey const& userSecret)
{
  auto const provisionalIdentity =
      Identity::extract<Identity::SecretProvisionalIdentity>(
          sidentity.string());

  if (provisionalIdentity.target != Identity::TargetType::Email &&
      provisionalIdentity.target != Identity::TargetType::PhoneNumber)
  {
    throw Errors::AssertionError(
        fmt::format(FMT_STRING("unsupported provisional identity target {:s}"),
                    provisionalIdentity.target));
  }

  if (TC_AWAIT(fetchProvisionalKeys(provisionalIdentity)))
    TC_RETURN((AttachResult{Tanker::Status::Ready, std::nullopt}));

  return claimProvisionalIdentity(provisionalIdentity, userSecret);
}

tc::cotask<void> Manager::verifyProvisionalIdentity(
    Verification::RequestWithVerif const& unlockRequest)
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
