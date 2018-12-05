#include <Generator/Resource.hpp>
#include <Generator/Utils.hpp>
#include <Tanker/Serialization/Serialization.hpp>
#include <Tanker/Share.hpp>

namespace Tanker
{

namespace Generator
{
Share::Share(Device const& sender, Device const& recipient, Resource res)
  : res{std::move(res)},
    sender(sender.deviceId),
    recipient(recipient.deviceId),
    privateSigKey(sender.sigKeys.privateKey),
    buffer(Tanker::Share::makeKeyPublishToDeviceToUser(
        sender.bgen, recipient.userKeys.publicKey, res.mac, res.key)),
    hash{Serialization::deserialize<Block>(buffer).hash()}
{
}
}
}
