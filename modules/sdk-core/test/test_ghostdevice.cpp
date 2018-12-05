#include <Tanker/GhostDevice.hpp>
#include <Tanker/Types/DeviceId.hpp>

#include <Helpers/Buffers.hpp>

#include <nlohmann/json.hpp>

#include <doctest.h>

using namespace Tanker;

TEST_CASE("it can unserialize a GhostDevice")
{
  GhostDevice gd{
      make<DeviceId>("deviddeviddeviddeviddeviddevidde"),
      make<Crypto::PrivateSignatureKey>(
          "sig  keysig  keysig  keysig  keysig  keysig  keysig  keysig  key"),
      make<Crypto::PrivateEncryptionKey>("enc  keyenc  keyenc  keyenc  key"),
  };

  auto const jsonGd = R"({
    "deviceId":"ZGV2aWRkZXZpZGRldmlkZGV2aWRkZXZpZGRldmlkZGU=",
    "privateSignatureKey":"c2lnICBrZXlzaWcgIGtleXNpZyAga2V5c2lnICBrZXlzaWcgIGtleXNpZyAga2V5c2lnICBrZXlzaWcgIGtleQ==",
    "privateEncryptionKey":"ZW5jICBrZXllbmMgIGtleWVuYyAga2V5ZW5jICBrZXk="
  })";

  CHECK(nlohmann::json::parse(jsonGd).get<GhostDevice>() == gd);
}

TEST_CASE("it can serialize and deserialize a GhostDevice")
{
  GhostDevice gd{
      make<DeviceId>("devid"),
      make<Crypto::PrivateSignatureKey>("sig key"),
      make<Crypto::PrivateEncryptionKey>("enc key"),
  };

  CHECK(nlohmann::json::parse(nlohmann::json(gd).dump()).get<GhostDevice>() ==
        gd);
}
