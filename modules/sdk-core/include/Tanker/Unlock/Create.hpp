#pragma once

#include <Tanker/Trustchain/Block.hpp>
#include <Tanker/Trustchain/TrustchainId.hpp>
#include <Tanker/Trustchain/UserId.hpp>

namespace Tanker
{
struct EncryptedUserKey;
struct DeviceKeys;
struct GhostDevice;

namespace Unlock
{
Trustchain::Block createValidatedDevice(
    Trustchain::TrustchainId const& trustchainId,
    Trustchain::UserId const& userId,
    GhostDevice const& ghostDevice,
    DeviceKeys const& deviceKeys,
    EncryptedUserKey const& encryptedUserKey);
}
}
