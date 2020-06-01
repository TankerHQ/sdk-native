#include <Tanker/Trustchain/Actions/DeviceCreation/v2.hpp>

#include <Tanker/Errors/Exception.hpp>
#include <Tanker/Serialization/Serialization.hpp>
#include <Tanker/Trustchain/Errors/Errc.hpp>

#include <nlohmann/json.hpp>

#include <stdexcept>
#include <tuple>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
DeviceCreation1 DeviceCreation2::asDeviceCreation1() const
{
  if (!_lastReset.is_null())
  {
    throw Errors::Exception(
        Errc::InvalidLastResetField,
        "cannot convert DeviceCreation2 to DeviceCreation1: lastReset field is "
        "not zero-filled");
  }
  return DeviceCreation1{
      _ephemeralPublicSignatureKey,
      _userId,
      _delegationSignature,
      _publicSignatureKey,
      _publicEncryptionKey,
  };
}

TANKER_TRUSTCHAIN_ACTION_DEFINE_SERIALIZATION(
    DeviceCreation2, TANKER_TRUSTCHAIN_ACTIONS_DEVICE_CREATION_V2_ATTRIBUTES)
TANKER_TRUSTCHAIN_ACTION_DEFINE_TO_JSON(
    DeviceCreation2, TANKER_TRUSTCHAIN_ACTIONS_DEVICE_CREATION_V2_ATTRIBUTES)
}
}
}
