#include <Tanker/ProvisionalUsers/Manager.hpp>

#include <Tanker/AttachResult.hpp>
#include <Tanker/Errors/AssertionError.hpp>
#include <Tanker/Errors/ServerErrc.hpp>
#include <Tanker/Format/Enum.hpp>
#include <Tanker/Format/Format.hpp>
#include <Tanker/Identity/Extract.hpp>
#include <Tanker/Log/Log.hpp>
#include <Tanker/Users/LocalUser.hpp>

#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/predicate.hpp>
#include <boost/algorithm/string/split.hpp>
#include <cppcodec/base64_url_unpadded.hpp>

TLOG_CATEGORY(ProvisionalUsers);

namespace Tanker
{
namespace ProvisionalUsers
{
Manager::Manager(Users::LocalUser* localUser,
                 Client* client,
                 ProvisionalUsers::Accessor* provisionalUsersAccessor,
                 ProvisionalUserKeysStore* provisionalUserKeysStore,
                 BlockGenerator* blockGenerator)
  : _localUser(localUser),
    _client(client),
    _provisionalUsersAccessor(provisionalUsersAccessor),
    _provisionalUserKeysStore(provisionalUserKeysStore),
    _blockGenerator(blockGenerator)
{
}

tc::cotask<AttachResult> Manager::attachProvisionalIdentity(
    Crypto::EncryptionKeyPair const& lastUserKey,
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
        _client->getVerifiedProvisionalIdentityKeys(Crypto::generichash(
            gsl::make_span(email).as_span<std::uint8_t const>())));
    if (tankerKeys)
    {
      auto block = _blockGenerator->provisionalIdentityClaim(
          _localUser->userId(),
          SecretProvisionalUser{provisionalIdentity.target,
                                provisionalIdentity.value,
                                provisionalIdentity.appEncryptionKeyPair,
                                tankerKeys->encryptionKeyPair,
                                provisionalIdentity.appSignatureKeyPair,
                                tankerKeys->signatureKeyPair},
          lastUserKey);
      TC_AWAIT(_client->pushBlock(block));
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

namespace
{
void matchProvisional(
    Unlock::Verification const& verification,
    Identity::SecretProvisionalIdentity const& provisionalIdentity)
{
  namespace bv = boost::variant2;
  namespace ba = boost::algorithm;

  if (!(bv::holds_alternative<Unlock::EmailVerification>(verification) ||
        bv::holds_alternative<OidcIdToken>(verification)))
    throw Errors::Exception(
        make_error_code(Errors::Errc::InvalidArgument),
        "unknown verification method for provisional identity");

  if (auto const emailVerification =
          bv::get_if<Unlock::EmailVerification>(&verification))
  {
    if (emailVerification->email != Email{provisionalIdentity.value})
      throw Errors::Exception(
          make_error_code(Errors::Errc::InvalidArgument),
          "verification email does not match provisional identity");
  }
  else if (auto const oidcIdToken = bv::get_if<OidcIdToken>(&verification))
  {
    std::string jwtEmail;
    try
    {
      std::vector<std::string> res;
      ba::split(res, *oidcIdToken, ba::is_any_of("."));
      jwtEmail = nlohmann::json::parse(
                     cppcodec::base64_url_unpadded::decode(res.at(1)))
                     .at("email");
    }
    catch (...)
    {
      throw Errors::Exception(make_error_code(Errors::Errc::InvalidArgument),
                              "Failed to parse verification oidcIdToken");
    }
    if (jwtEmail != provisionalIdentity.value)
      throw Errors::Exception(
          make_error_code(Errors::Errc::InvalidArgument),
          "verification does not match provisional identity");
  }
}
}

tc::cotask<void> Manager::verifyProvisionalIdentity(
    Crypto::EncryptionKeyPair const& lastUserKey,
    Unlock::Verification const& verification)
{
  if (!_provisionalIdentity.has_value())
    throw formatEx(
        Errors::Errc::PreconditionFailed,
        "cannot call verifyProvisionalIdentity without having called "
        "attachProvisionalIdentity before");
  matchProvisional(verification, _provisionalIdentity.value());
  auto const tankerKeys = TC_AWAIT(_client->getProvisionalIdentityKeys(
      verification, _localUser->userSecret()));
  if (!tankerKeys)
  {
    TINFO("Nothing to claim");
    TC_RETURN();
  }
  auto block = _blockGenerator->provisionalIdentityClaim(
      _localUser->userId(),
      SecretProvisionalUser{_provisionalIdentity->target,
                            _provisionalIdentity->value,
                            _provisionalIdentity->appEncryptionKeyPair,
                            tankerKeys->encryptionKeyPair,
                            _provisionalIdentity->appSignatureKeyPair,
                            tankerKeys->signatureKeyPair},
      lastUserKey);
  TC_AWAIT(_client->pushBlock(block));
  _provisionalIdentity.reset();
  TC_AWAIT(_provisionalUsersAccessor->refreshKeys());
}
}
}
