#pragma once

#include <Tanker/Crypto/BasicCryptographicType.hpp>
#include <Tanker/Crypto/Mac.hpp>

namespace Tanker::Crypto
{
class SimpleResourceId : public BasicCryptographicType<SimpleResourceId, Mac::arraySize>
{
  using base_t::base_t;
};
}
