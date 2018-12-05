#pragma once

#include <Tanker/Crypto/Types.hpp>

#include <tconcurrent/coroutine.hpp>

namespace Tanker
{
class ContactStore;
class ResourceKeyStore;
class UserKeyStore;
class GroupStore;
struct Entry;

namespace ReceiveKey
{
tc::cotask<void> onKeyToDeviceReceived(
    ContactStore const& contactDeviceStore,
    ResourceKeyStore& resourceKeyStore,
    Crypto::PrivateEncryptionKey const& selfDevicePrivateEncryptionKey,
    Entry const& entry);

tc::cotask<void> decryptAndStoreKey(ResourceKeyStore& resourceKeyStore,
                                    UserKeyStore const& userKeyStore,
                                    GroupStore const& groupStore,
                                    Entry const& entry);
}
}
