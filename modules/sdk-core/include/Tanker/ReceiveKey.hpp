#pragma once

#include <Tanker/Crypto/PrivateEncryptionKey.hpp>
#include <Tanker/ProvisionalUsers/IAccessor.hpp>
#include <Tanker/Trustchain/Actions/KeyPublish.hpp>

#include <tconcurrent/coroutine.hpp>

namespace Tanker
{

namespace Groups
{
class IAccessor;
}

namespace Users
{
class ContactStore;
class LocalUser;
}

class ResourceKeyStore;
struct Entry;

namespace ReceiveKey
{
tc::cotask<void> onKeyToDeviceReceived(
    Users::ContactStore const& contactDeviceStore,
    ResourceKeyStore& resourceKeyStore,
    Crypto::PrivateEncryptionKey const& selfDevicePrivateEncryptionKey,
    Entry const& entry);

tc::cotask<void> decryptAndStoreKey(
    ResourceKeyStore& resourceKeyStore,
    Users::LocalUser const& localUser,
    Groups::IAccessor& GroupAccessor,
    ProvisionalUsers::IAccessor& provisionalUsersAccessor,
    Trustchain::Actions::KeyPublish const& kp);
}
}
