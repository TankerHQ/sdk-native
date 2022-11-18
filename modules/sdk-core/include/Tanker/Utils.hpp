#pragma once

#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Errors/Exception.hpp>
#include <Tanker/Trustchain/GroupId.hpp>
#include <Tanker/Types/SGroupId.hpp>

#include <mgs/base64.hpp>
#include <mgs/codecs/concepts/codec.hpp>

#include <range/v3/range/conversion.hpp>
#include <range/v3/view/transform.hpp>

#include <date/date.h>

#include <algorithm>
#include <type_traits>
#include <vector>

namespace Tanker
{
template <typename Codec, typename T, typename String>
T decodeArgument(String const& b64, std::string const& argName)
{
  using namespace Tanker::Errors;

  try
  {
    return Codec::template decode<T>(b64);
  }
  catch (mgs::exceptions::exception const&)
  {
    throw formatEx(
        Errc::InvalidArgument, "{} has an invalid value: {}", argName, b64);
  }
  catch (Errors::Exception const& e)
  {
    if (e.errorCode() == Crypto::Errc::InvalidBufferSize)
    {
      throw formatEx(
          Errc::InvalidArgument, "{} has an invalid value: {}", argName, b64);
    }
    throw;
  }
}

inline uint64_t secondsSinceEpoch()
{
  using namespace std::chrono;

  auto localTime = time_point_cast<std::chrono::seconds>(system_clock::now());
  auto dateSeconds = date::sys_seconds{localTime};

  // date::sys_seconds documents that its epoch is the unix epoch everywhere
  return dateSeconds.time_since_epoch().count();
}
}
