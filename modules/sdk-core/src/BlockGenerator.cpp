#include <Tanker/BlockGenerator.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Groups/EntryGenerator.hpp>
#include <Tanker/Identity/Delegation.hpp>
#include <Tanker/Serialization/Serialization.hpp>
#include <Tanker/Trustchain/Action.hpp>
#include <Tanker/Trustchain/ClientEntry.hpp>
#include <Tanker/Trustchain/DeviceId.hpp>
#include <Tanker/Trustchain/TrustchainId.hpp>
#include <Tanker/Trustchain/UserId.hpp>
#include <Tanker/Users/EntryGenerator.hpp>

#include <stdexcept>

using namespace Tanker::Trustchain;
using namespace Tanker::Trustchain::Actions;

namespace Tanker
{
BlockGenerator::BlockGenerator(
    Trustchain::TrustchainId const& trustchainId,
    Crypto::PrivateSignatureKey const& privateSignatureKey,
    Trustchain::DeviceId const& deviceId)
  : _trustchainId(trustchainId),
    _privateSignatureKey(privateSignatureKey),
    _deviceId(deviceId)
{
}

Trustchain::TrustchainId const& BlockGenerator::trustchainId() const noexcept
{
  return _trustchainId;
}

void BlockGenerator::setDeviceId(Trustchain::DeviceId const& deviceId)
{
  _deviceId = deviceId;
}

Trustchain::DeviceId const& BlockGenerator::deviceId() const
{
  return _deviceId;
}

Crypto::PrivateSignatureKey const& BlockGenerator::signatureKey() const noexcept
{
  return _privateSignatureKey;
}
}
