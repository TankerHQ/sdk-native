#pragma once

#include <Tanker/Crypto/PrivateEncryptionKey.hpp>

#include <tconcurrent/coroutine.hpp>

namespace Tanker
{
class ContactStore;
class ResourceKeyStore;
class UserKeyStore;
class GroupStore;
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
    GroupStore const& groupStore,
    ProvisionalUserKeysStore const& provisionalUserKeysStore,
    Entry const& entry);
}
}
