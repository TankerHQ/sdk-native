#include <Tanker/GhostDevice.hpp>

#include <Tanker/Encryptor/v2.hpp>
#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Errors/Exception.hpp>
#include <Tanker/Users/EntryGenerator.hpp>

#include <nlohmann/json.hpp>

#include <tuple>

namespace Tanker
{
DeviceKeys generateGhostDeviceKeys(
    std::optional<Verification::Verification> const& verification)
{
  if (verification &&
      boost::variant2::holds_alternative<VerificationKey>(*verification))
  {
    return GhostDevice::create(
               boost::variant2::get<VerificationKey>(*verification))
        .toDeviceKeys();
  }
  return DeviceKeys::create();
}

GeneratedGhostDevice generateGhostDevice(
    Identity::SecretPermanentIdentity const& identity,
    DeviceKeys const& ghostDeviceKeys)
{
  auto const ghostDevice = GhostDevice::create(ghostDeviceKeys);

  auto const userKeyPair = Crypto::makeEncryptionKeyPair();
  auto const userCreationEntry =
      Users::createNewUserAction(identity.trustchainId,
                                 identity.delegation,
                                 ghostDeviceKeys.signatureKeyPair.publicKey,
                                 ghostDeviceKeys.encryptionKeyPair.publicKey,
                                 userKeyPair);

  auto const verificationKeyToSend = ghostDevice.toVerificationKey();
  std::vector<uint8_t> encryptedVerificationKey(
      EncryptorV2::encryptedSize(verificationKeyToSend.size()));
  EncryptorV2::encryptSync(
      encryptedVerificationKey.data(),
      gsl::make_span(verificationKeyToSend).as_span<uint8_t const>(),
      identity.userSecret);

  return {
      userCreationEntry,
      encryptedVerificationKey,
      ghostDevice,
      userKeyPair,
  };
}

GhostDevice GhostDevice::create(VerificationKey const& key)
try
{
  return nlohmann::json::parse(mgs::base64::decode(key)).get<GhostDevice>();
}
catch (std::exception const& e)
{
  throw Errors::Exception(make_error_code(Errors::Errc::InvalidVerification),
                          "invalid verification key");
}

GhostDevice GhostDevice::create(DeviceKeys const& keys)
{
  return GhostDevice{keys.signatureKeyPair.privateKey,
                     keys.encryptionKeyPair.privateKey};
}

DeviceKeys GhostDevice::toDeviceKeys() const
{
  return DeviceKeys::create(this->privateSignatureKey,
                            this->privateEncryptionKey);
}

VerificationKey GhostDevice::toVerificationKey() const
{
  return mgs::base64::encode<VerificationKey>(nlohmann::json(*this).dump());
}

void from_json(nlohmann::json const& j, GhostDevice& d)
{
  j.at("privateSignatureKey").get_to(d.privateSignatureKey);
  j.at("privateEncryptionKey").get_to(d.privateEncryptionKey);
}

void to_json(nlohmann::json& j, GhostDevice const& d)
{
  j["privateSignatureKey"] = d.privateSignatureKey;
  j["privateEncryptionKey"] = d.privateEncryptionKey;
}

bool operator==(GhostDevice const& l, GhostDevice const& r)
{
  return std::tie(l.privateSignatureKey, l.privateEncryptionKey) ==
         std::tie(r.privateSignatureKey, r.privateEncryptionKey);
}

bool operator!=(GhostDevice const& l, GhostDevice const& r)
{
  return !(l == r);
}
}
