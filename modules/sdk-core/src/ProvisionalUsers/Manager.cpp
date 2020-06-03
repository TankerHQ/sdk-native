#include <Tanker/ProvisionalUsers/Manager.hpp>

#include <Tanker/AttachResult.hpp>
#include <Tanker/Errors/AssertionError.hpp>
#include <Tanker/Errors/ServerErrc.hpp>
#include <Tanker/Format/Enum.hpp>
#include <Tanker/Format/Format.hpp>
#include <Tanker/Identity/Extract.hpp>
#include <Tanker/Log/Log.hpp>
#include <Tanker/ProvisionalUsers/IRequester.hpp>
#include <Tanker/ProvisionalUsers/ProvisionalUserKeysStore.hpp>
#include <Tanker/Pusher.hpp>
#include <Tanker/Users/EntryGenerator.hpp>
#include <Tanker/Users/LocalUser.hpp>
#include <Tanker/Users/LocalUserAccessor.hpp>

TLOG_CATEGORY(ProvisionalUsers);

namespace Tanker
{
namespace ProvisionalUsers
{
Manager::Manager(Users::ILocalUserAccessor* localUserAccessor,
                 Pusher* pusher,
                 IRequester* requester,
                 ProvisionalUsers::Accessor* provisionalUsersAccessor,
                 ProvisionalUserKeysStore* provisionalUserKeysStore,
                 Trustchain::TrustchainId const& trustchainId)
  : _localUserAccessor(localUserAccessor),
    _pusher(pusher),
    _requester(requester),
    _provisionalUsersAccessor(provisionalUsersAccessor),
    _provisionalUserKeysStore(provisionalUserKeysStore),
    _trustchainId(trustchainId)
{
}

tc::cotask<AttachResult> Manager::attachProvisionalIdentity(
    SSecretProvisionalIdentity const& sidentity)
{
  auto const provisionalIdentity =
      Identity::extract<Identity::SecretProvisionalIdentity>(
          sidentity.string());
  if (provisionalIdentity.target != Identity::TargetType::Email)
  {
    throw Errors::AssertionError(
        fmt::format(TFMT("unsupported provisional identity target {:s}"),
                    provisionalIdentity.target));
  }
  TC_AWAIT(_provisionalUsersAccessor->refreshKeys());
  if (TC_AWAIT(_provisionalUserKeysStore
                   ->findProvisionalUserKeysByAppPublicEncryptionKey(
                       provisionalIdentity.appEncryptionKeyPair.publicKey)))
  {
    TC_RETURN((AttachResult{Tanker::Status::Ready, std::nullopt}));
  }
  auto const email = Email{provisionalIdentity.value};
  try
  {
    auto const tankerKeys = TC_AWAIT(
        _requester->getVerifiedProvisionalIdentityKeys(Crypto::generichash(
            gsl::make_span(email).as_span<std::uint8_t const>())));
    if (tankerKeys)
    {
      auto const localUser = TC_AWAIT(_localUserAccessor->pull());
      auto const clientEntry = Users::createProvisionalIdentityClaimAction(
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
      TC_AWAIT(_pusher->pushBlock(clientEntry));
    }
    TC_RETURN((AttachResult{Tanker::Status::Ready, std::nullopt}));
  }
  catch (Tanker::Errors::Exception const& e)
  {
    if (e.errorCode() == Errors::ServerErrc::VerificationNeeded)
    {
      _provisionalIdentity = provisionalIdentity;
      TC_RETURN(
          (AttachResult{Tanker::Status::IdentityVerificationNeeded, email}));
    }
    throw;
  }
  throw Errors::AssertionError("unreachable code");
}

tc::cotask<void> Manager::verifyProvisionalIdentity(
    Unlock::Request const& unlockRequest)
{
  auto const tankerKeys =
      TC_AWAIT(_requester->getProvisionalIdentityKeys(unlockRequest));
  if (!tankerKeys)
  {
    TINFO("Nothing to claim");
    TC_RETURN();
  }

  auto const localUser = TC_AWAIT(_localUserAccessor->pull());
  auto const clientEntry = Users::createProvisionalIdentityClaimAction(
      _trustchainId,
      localUser.deviceId(),
      localUser.deviceKeys().signatureKeyPair.privateKey,
      localUser.userId(),
      ProvisionalUsers::SecretUser{_provisionalIdentity->target,
                                   _provisionalIdentity->value,
                                   _provisionalIdentity->appEncryptionKeyPair,
                                   tankerKeys->encryptionKeyPair,
                                   _provisionalIdentity->appSignatureKeyPair,
                                   tankerKeys->signatureKeyPair},
      localUser.currentKeyPair());
  TC_AWAIT(_pusher->pushBlock(clientEntry));

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
