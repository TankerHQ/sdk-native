#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Errors/AssertionError.hpp>
#include <Tanker/Types/Overloaded.hpp>
#include <Tanker/Users/EntryGenerator.hpp>
#include <date/date.h>

namespace Tanker::Users
{
using namespace Tanker::Trustchain;
using Trustchain::Actions::DeviceCreation;
using Trustchain::Actions::DeviceCreation1;
using Trustchain::Actions::DeviceCreation3;

namespace
{
Crypto::Hash verificationTargetHash(
    Verification::Verification const& verification, DeviceId const& deviceId)
{
  Crypto::Hash target;
  if (auto const emailVerif =
          boost::variant2::get_if<Verification::ByEmail>(&verification))
  {
    target = Crypto::generichash(
        gsl::make_span(emailVerif->email).as_span<uint8_t const>());
  }
  else if (auto const phoneNumberVerif =
               boost::variant2::get_if<Verification::ByPhoneNumber>(
                   &verification))
  {
    target = Crypto::generichash(
        gsl::make_span(phoneNumberVerif->phoneNumber).as_span<uint8_t const>());
  }
  else
  {
    target.fill(0);
  }
  return target;
}

Trustchain::Actions::VerificationMethodType verificationMethodType(
    Verification::Verification const& verification)
{
  using Trustchain::Actions::VerificationMethodType;
  return boost::variant2::visit(
      overloaded{
          [](Verification::ByEmail const& v) -> VerificationMethodType {
            return VerificationMethodType::Email;
          },
          [](Verification::ByPhoneNumber const& v) -> VerificationMethodType {
            return VerificationMethodType::PhoneNumber;
          },
          [](Passphrase const& p) -> VerificationMethodType {
            return VerificationMethodType::Passphrase;
          },
          [](E2ePassphrase const& p) -> VerificationMethodType {
            return VerificationMethodType::E2ePassphrase;
          },
          [](VerificationKey const& v) -> VerificationMethodType {
            return VerificationMethodType::VerificationKey;
          },
          [](OidcIdToken const& v) -> VerificationMethodType {
            return VerificationMethodType::OidcIdToken;
          },
          [](PreverifiedEmail const& v) -> VerificationMethodType {
            throw Errors::AssertionError(
                "No verification method type for preverified email");
          },
          [](PreverifiedPhoneNumber const& v) -> VerificationMethodType {
            throw Errors::AssertionError(
                "No verification method type for preverified phone number");
          },
      },
      verification);
}

uint64_t secondsSinceEpoch()
{
  // LEGACY:
  // While C++ provides a `time_since_epoch` function, unlike other advanced
  // concepts such as "files and folders" introduced relatively early (C++17),
  // "unix timestamps" are still considered a downright esoteric idea,
  // so naturally time_since_epoch uses an implementation-defined
  // epoch before C++20, which makes its return value unpredictable.
  // Instead, we use date.h, which is theoretically usable.
  using namespace std::chrono;

  auto localTime = time_point_cast<std::chrono::seconds>(system_clock::now());
  auto dateSeconds = date::sys_seconds{localTime};

  // date::sys_seconds documents that its epoch is the unix epoch everywhere
  return dateSeconds.time_since_epoch().count();
}
}

namespace
{
DeviceCreation3 createDeviceAction(
    TrustchainId const& trustchainId,
    Crypto::Hash const& author,
    Identity::Delegation const& delegation,
    Crypto::PublicSignatureKey const& signatureKey,
    Crypto::PublicEncryptionKey const& encryptionKey,
    Crypto::EncryptionKeyPair const& userEncryptionKeys,
    DeviceCreation::DeviceType deviceType)
{
  auto const sealedPrivateEncryptionKey =
      Crypto::sealEncrypt(userEncryptionKeys.privateKey, encryptionKey);

  return DeviceCreation::v3{
      trustchainId,
      delegation.ephemeralKeyPair.publicKey,
      delegation.userId,
      delegation.signature,
      signatureKey,
      encryptionKey,
      userEncryptionKeys.publicKey,
      sealedPrivateEncryptionKey,
      deviceType == DeviceCreation::DeviceType::GhostDevice,
      author,
      delegation.ephemeralKeyPair.privateKey,
  };
}
}

DeviceCreation1 createDeviceV1Action(
    TrustchainId const& trustchainId,
    Crypto::Hash const& author,
    Identity::Delegation const& delegation,
    Crypto::PublicSignatureKey const& signatureKey,
    Crypto::PublicEncryptionKey const& encryptionKey)
{
  return DeviceCreation::v1{trustchainId,
                            delegation.ephemeralKeyPair.publicKey,
                            delegation.userId,
                            delegation.signature,
                            signatureKey,
                            encryptionKey,
                            author,
                            delegation.ephemeralKeyPair.privateKey};
}

DeviceCreation3 createNewUserAction(
    TrustchainId const& trustchainId,
    Identity::Delegation const& delegation,
    Crypto::PublicSignatureKey const& signatureKey,
    Crypto::PublicEncryptionKey const& encryptionKey,
    Crypto::EncryptionKeyPair const& userEncryptionKeys)
{
  return createDeviceAction(trustchainId,
                            static_cast<Crypto::Hash>(trustchainId),
                            delegation,
                            signatureKey,
                            encryptionKey,
                            userEncryptionKeys,
                            DeviceCreation::DeviceType::GhostDevice);
}

DeviceCreation3 createNewDeviceAction(
    TrustchainId const& trustchainId,
    DeviceId const& author,
    Identity::Delegation const& delegation,
    Crypto::PublicSignatureKey const& signatureKey,
    Crypto::PublicEncryptionKey const& encryptionKey,
    Crypto::EncryptionKeyPair const& userEncryptionKeys)
{
  return createDeviceAction(trustchainId,
                            static_cast<Crypto::Hash>(author),
                            delegation,
                            signatureKey,
                            encryptionKey,
                            userEncryptionKeys,
                            DeviceCreation::DeviceType::Device);
}

DeviceCreation3 createNewGhostDeviceAction(
    TrustchainId const& trustchainId,
    DeviceId const& author,
    Identity::Delegation const& delegation,
    Crypto::PublicSignatureKey const& signatureKey,
    Crypto::PublicEncryptionKey const& encryptionKey,
    Crypto::EncryptionKeyPair const& userEncryptionKeys)
{
  return createDeviceAction(trustchainId,
                            static_cast<Crypto::Hash>(author),
                            delegation,
                            signatureKey,
                            encryptionKey,
                            userEncryptionKeys,
                            DeviceCreation::DeviceType::GhostDevice);
}

Actions::SessionCertificate createSessionCertificate(
    TrustchainId const& trustchainId,
    DeviceId const& deviceId,
    Verification::Verification const& verification,
    Crypto::PrivateSignatureKey const& signatureKey)
{
  auto verifTarget = verificationTargetHash(verification, deviceId);
  auto methodType = verificationMethodType(verification);
  auto const sessionSignatureKeyPair = Crypto::makeSignatureKeyPair();

  return Actions::SessionCertificate(trustchainId,
                                     sessionSignatureKeyPair.publicKey,
                                     secondsSinceEpoch(),
                                     methodType,
                                     verifTarget,
                                     static_cast<Crypto::Hash>(deviceId),
                                     signatureKey);
}

Actions::ProvisionalIdentityClaim createProvisionalIdentityClaimAction(
    TrustchainId const& trustchainId,
    DeviceId const& deviceId,
    Crypto::PrivateSignatureKey const& deviceSignatureKey,
    UserId const& userId,
    ProvisionalUsers::SecretUser const& provisionalUser,
    Crypto::EncryptionKeyPair const& userKeyPair)
{
  std::vector<std::uint8_t> keysToEncrypt(
      Crypto::PrivateEncryptionKey::arraySize * 2);

  auto it = std::copy(provisionalUser.appEncryptionKeyPair.privateKey.begin(),
                      provisionalUser.appEncryptionKeyPair.privateKey.end(),
                      keysToEncrypt.data());
  std::copy(provisionalUser.tankerEncryptionKeyPair.privateKey.begin(),
            provisionalUser.tankerEncryptionKeyPair.privateKey.end(),
            it);

  return Actions::ProvisionalIdentityClaim{
      trustchainId,
      userId,
      provisionalUser.appSignatureKeyPair,
      provisionalUser.tankerSignatureKeyPair,
      userKeyPair.publicKey,
      Crypto::sealEncrypt<
          Actions::ProvisionalIdentityClaim::SealedPrivateEncryptionKeys>(
          keysToEncrypt, userKeyPair.publicKey),
      deviceId,
      deviceSignatureKey,
  };
}

Trustchain::Actions::KeyPublishToProvisionalUser
createKeyPublishToProvisionalUserAction(
    TrustchainId const& trustchainId,
    DeviceId const& deviceId,
    Crypto::PrivateSignatureKey const& deviceSignatureKey,
    Crypto::PublicSignatureKey const& appPublicSignatureKey,
    Crypto::PublicSignatureKey const& tankerPublicSignatureKey,
    Crypto::SimpleResourceId const& resourceId,
    Crypto::TwoTimesSealedSymmetricKey const& symKey)
{
  return Trustchain::Actions::KeyPublishToProvisionalUser{
      trustchainId,
      appPublicSignatureKey,
      tankerPublicSignatureKey,
      resourceId,
      symKey,
      static_cast<Crypto::Hash>(deviceId),
      deviceSignatureKey,
  };
}

Trustchain::Actions::KeyPublishToUser createKeyPublishToUserAction(
    TrustchainId const& trustchainId,
    DeviceId const& deviceId,
    Crypto::PrivateSignatureKey const& deviceSignatureKey,
    Crypto::SealedSymmetricKey const& symKey,
    Crypto::SimpleResourceId const& resourceId,
    Crypto::PublicEncryptionKey const& recipientPublicEncryptionKey)
{
  return Trustchain::Actions::KeyPublishToUser{
      trustchainId,
      recipientPublicEncryptionKey,
      resourceId,
      symKey,
      static_cast<Crypto::Hash>(deviceId),
      deviceSignatureKey};
}
}
