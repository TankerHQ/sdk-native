#pragma once

#include <Tanker/Crypto/PrivateEncryptionKey.hpp>
#include <Tanker/ProvisionalUsers/IAccessor.hpp>
#include <Tanker/ResourceKeys/KeysResult.hpp>
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
class ILocalUserAccessor;
}

namespace ResourceKeys
{
class Store;
}

namespace ReceiveKey
{
tc::cotask<ResourceKeys::KeyResult> decryptAndStoreKey(
    ResourceKeys::Store& resourceKeyStore,
    Users::ILocalUserAccessor& localUserAccessor,
    Groups::IAccessor& GroupAccessor,
    ProvisionalUsers::IAccessor& provisionalUsersAccessor,
    Trustchain::Actions::KeyPublish const& kp);
}
}
