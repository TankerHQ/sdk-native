#pragma once

#include <Tanker/Crypto/PublicEncryptionKey.hpp>
#include <Tanker/Crypto/SealedPrivateEncryptionKey.hpp>
#include <Tanker/Serialization/SerializedSource.hpp>
#include <Tanker/Trustchain/Actions/DeviceRevocation/v1.hpp>
#include <Tanker/Trustchain/Actions/DeviceRevocation/v2.hpp>
#include <Tanker/Trustchain/Actions/Nature.hpp>
#include <Tanker/Trustchain/DeviceId.hpp>
#include <Tanker/Trustchain/Preprocessor/Actions/VariantImplementation.hpp>

#include <boost/variant2/variant.hpp>
#include <nlohmann/json_fwd.hpp>

#include <cstddef>
#include <cstdint>
#include <utility>
#include <vector>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
class DeviceRevocation
{
  TANKER_TRUSTCHAIN_ACTION_VARIANT_IMPLEMENTATION(DeviceRevocation,
                                                  (DeviceRevocation1,
                                                   DeviceRevocation2),
                                                  (deviceId, DeviceId))

public:
  using v1 = DeviceRevocation1;
  using v2 = DeviceRevocation2;

  Nature nature() const;

private:
  friend std::uint8_t* to_serialized(std::uint8_t*, DeviceRevocation const&);
  friend std::size_t serialized_size(DeviceRevocation const&);
  friend void to_json(nlohmann::json&, DeviceRevocation const&);
};

// The nature is not present in the wired payload.
// Therefore there is no from_serialized overload for DeviceRevocation.
std::uint8_t* to_serialized(std::uint8_t*, DeviceRevocation const&);
std::size_t serialized_size(DeviceRevocation const&);

void to_json(nlohmann::json&, DeviceRevocation const&);
}
}
}
