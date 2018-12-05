#include <Generator/Device.hpp>

#include <Generator/BlockTypes.hpp>
#include <Tanker/Block.hpp>
#include <Tanker/BlockGenerator.hpp>
#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Crypto/Types.hpp>
#include <Tanker/Crypto/base64.hpp>
#include <Tanker/GhostDevice.hpp>
#include <Tanker/Serialization/Serialization.hpp>
#include <Tanker/Types/DeviceId.hpp>
#include <Tanker/Types/UnlockKey.hpp>
#include <Tanker/Types/UserId.hpp>
#include <Tanker/UserToken/Delegation.hpp>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <iterator>

namespace Tanker
{
namespace Generator
{
Device::Device(BuildFrom, Device const& d)
  : sigKeys{Crypto::makeSignatureKeyPair()},
    encKeys{Crypto::makeEncryptionKeyPair()},
    userKeys{d.userKeys},
    bgen{d.bgen}, // deviceId will be fixed later
    userId{d.userId},
    obfuscatedId{d.obfuscatedId},
    delegation{UserToken::makeDelegation(obfuscatedId, d.sigKeys.privateKey)},
    author{d.deviceId},
    buffer{bgen.addDevice(
        delegation, sigKeys.publicKey, encKeys.publicKey, d.userKeys)},
    deviceId{Serialization::deserialize<Tanker::Block>(buffer).hash()}
{
  bgen.setDeviceId(deviceId);
}

Device::Device(Ghost, Device const& d)
  : sigKeys{Crypto::makeSignatureKeyPair()},
    encKeys{Crypto::makeEncryptionKeyPair()},
    userKeys{d.userKeys},
    bgen{d.bgen}, // deviceId will be fixed later
    userId{d.userId},
    obfuscatedId{d.obfuscatedId},
    delegation{UserToken::makeDelegation(obfuscatedId, d.sigKeys.privateKey)},
    author{d.deviceId},
    buffer{bgen.addGhostDevice(
        delegation, sigKeys.publicKey, encKeys.publicKey, d.userKeys)},
    deviceId{Serialization::deserialize<Tanker::Block>(buffer).hash()}
{
  bgen.setDeviceId(deviceId);
}

Device::Device(SUserId const& uid,
               TrustchainId const& trustchainId,
               Crypto::PrivateSignatureKey const& trustchainPrivateKey)
  : sigKeys{Crypto::makeSignatureKeyPair()},
    encKeys{Crypto::makeEncryptionKeyPair()},
    userKeys{Crypto::makeEncryptionKeyPair()},
    bgen{trustchainId, sigKeys.privateKey, {}},
    userId{uid},
    obfuscatedId{obfuscateUserId(uid, trustchainId)},
    delegation{UserToken::makeDelegation(obfuscatedId, trustchainPrivateKey)},
    author{std::move(trustchainId)},
    buffer{bgen.addUser(
        delegation, sigKeys.publicKey, encKeys.publicKey, userKeys)},
    deviceId{Serialization::deserialize<Tanker::Block>(buffer).hash()}
{
  bgen.setDeviceId(deviceId);
}

Device Device::makeDevice() const
{
  return {Device::buildFrom, *this};
}

UnlockKey Device::asUnlockKey() const
{
  return UnlockKey{Tanker::base64::encode(
      nlohmann::json(
          GhostDevice{deviceId, sigKeys.privateKey, encKeys.privateKey})
          .dump())};
}

Devices Device::with(DeviceQuant count) &&
{
  Devices devices;
  devices.reserve(count.value);
  devices.push_back(std::move(*this));
  auto& that = devices.front();
  std::generate_n(std::back_inserter(devices), count.value - 1, [&] {
    return Device{Device::buildFrom, that};
  });
  return devices;
}

Devices Device::with(UnlockPassword) &&
{
  Devices devices;
  devices.reserve(2);
  devices.emplace_back(std::move(*this));
  devices.emplace_back(Device::Ghost{}, devices.front());
  return devices;
}

Device Device::make(UnlockPassword) const
{
  return {ghost, *this};
}

} /* Generator */
} /* Tanker */
