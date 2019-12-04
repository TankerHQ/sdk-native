#pragma once

#include <Tanker/Crypto/PrivateEncryptionKey.hpp>
#include <Tanker/Trustchain/Actions/KeyPublish.hpp>

#include <tconcurrent/coroutine.hpp>

namespace Tanker
{
namespace Groups
{
class IAccessor;
}
class ContactStore;
class ResourceKeyStore;
class UserKeyStore;
class ProvisionalUserKeysStore;
struct Entry;

namespace ReceiveKey
{
tc::cotask<void> onKeyToDeviceReceived(
    ContactStore const& contactDeviceStore,
    ResourceKeyStore& resourceKeyStore,
    Crypto::PrivateEncryptionKey const& selfDevicePrivateEncryptionKey,
    Entry const& entry);

tc::cotask<void> decryptAndStoreKey(
    ResourceKeyStore& resourceKeyStore,
    UserKeyStore const& userKeyStore,
    Groups::IAccessor& GroupAccessor,
    ProvisionalUserKeysStore const& provisionalUserKeysStore,
    Trustchain::Actions::KeyPublish const& kp);
}
}
