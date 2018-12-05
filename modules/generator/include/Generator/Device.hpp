#pragma once

#include <Generator/BlockTypes.hpp>

#include <Tanker/BlockGenerator.hpp>
#include <Tanker/Crypto/Types.hpp>
#include <Tanker/Types/DeviceId.hpp>
#include <Tanker/Types/TrustchainId.hpp>
#include <Tanker/Types/UnlockKey.hpp>
#include <Tanker/Types/UserId.hpp>
#include <Tanker/UserToken/Delegation.hpp>

#include <cstdint>
#include <string>
#include <vector>

namespace Tanker
{
namespace Generator
{
struct Device
{
  Crypto::SignatureKeyPair sigKeys;
  Crypto::EncryptionKeyPair encKeys;
  Crypto::EncryptionKeyPair userKeys;
  BlockGenerator bgen;
  SUserId userId;
  UserId obfuscatedId;
  UserToken::Delegation delegation;
  Crypto::Hash author;
  std::vector<uint8_t> buffer;
  DeviceId deviceId;

private:
  Device(Device const&) = delete;
  Device const& operator=(Device const&) = delete;
  static constexpr enum class BuildFrom {} buildFrom{};
  static constexpr enum class Ghost {} ghost{};

public:
  Device(BuildFrom, Device const& device);
  Device(Ghost, Device const& device);

  Device(Device&&) = default;
  Device& operator=(Device&&) = default;
  Device(SUserId const& uid,
         TrustchainId const& trustchainId,
         Crypto::PrivateSignatureKey const& trustchainPrivateKey);
  Device makeDevice() const;
  std::vector<Device> with(DeviceQuant d) &&;
  std::vector<Device> with(UnlockPassword) &&;
  UnlockKey asUnlockKey() const;
  Device make(UnlockPassword) const;
};

using Devices = std::vector<Device>;
}
}
