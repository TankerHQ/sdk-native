#include <Tanker/Actions/KeyPublishToDevice.hpp>

#include <Tanker/Index.hpp>
#include <Tanker/Nature.hpp>
#include <Tanker/Serialization/Serialization.hpp>
#include <Tanker/Serialization/SerializedSource.hpp>
#include <Tanker/Serialization/Varint.hpp>
#include <Tanker/Types/DeviceId.hpp>

#include <gsl-lite.hpp>
#include <nlohmann/json.hpp>

#include <stdexcept>
#include <tuple>
#include <vector>

namespace Tanker
{
Nature KeyPublishToDevice::nature() const
{
  return Nature::KeyPublishToDevice;
}

std::vector<Index> KeyPublishToDevice::makeIndexes() const
{
  return {};
}

bool operator==(KeyPublishToDevice const& l, KeyPublishToDevice const& r)
{
  return std::tie(l.recipient, l.mac, l.key) ==
         std::tie(r.recipient, r.mac, r.key);
}

bool operator!=(KeyPublishToDevice const& l, KeyPublishToDevice const& r)
{
  return !(l == r);
}

KeyPublishToDevice deserializeKeyPublishToDevice(gsl::span<uint8_t const> data)
{
  KeyPublishToDevice out;
  Serialization::SerializedSource ss{data};

  out.recipient = Serialization::deserialize<DeviceId>(ss);
  out.mac = Serialization::deserialize<Crypto::Mac>(ss);
  auto const keySize = ss.read_varint();
  if (keySize != out.key.size())
    throw std::runtime_error("invalid size for encrypted key: " +
                             std::to_string(keySize));
  out.key = Serialization::deserialize<Crypto::EncryptedSymmetricKey>(ss);

  if (!ss.eof())
    throw std::runtime_error("trailing garbage at end of DeviceCreation");

  return out;
}

std::uint8_t* to_serialized(std::uint8_t* it, KeyPublishToDevice const& kp)
{
  it = Serialization::serialize(it, kp.recipient);
  it = Serialization::serialize(it, kp.mac);
  it = Serialization::varint_write(it, kp.key.size());
  return Serialization::serialize(it, kp.key);
}

void to_json(nlohmann::json& j, KeyPublishToDevice const& kp)
{
  j["recipient"] = kp.recipient;
  j["mac"] = kp.mac;
  j["key"] = kp.key;
}
}
