#pragma once

#include <Tanker/Crypto/BasicCryptographicType.hpp>

namespace Tanker::Crypto
{
class SubkeySeed : public BasicCryptographicType<SubkeySeed, 16>
{
  using base_t::base_t;
};
}
