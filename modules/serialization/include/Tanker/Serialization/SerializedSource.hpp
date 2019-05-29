#pragma once

#include <cstdint>

#include <gsl-lite.hpp>

#include <Tanker/Errors/Exception.hpp>
#include <Tanker/Serialization/Errors/Errc.hpp>
#include <Tanker/Serialization/Varint.hpp>

namespace Tanker
{
namespace Serialization
{
class SerializedSource
{
public:
  SerializedSource() = default;

  SerializedSource(gsl::span<std::uint8_t const> sp) : _sp(sp)
  {
  }

  gsl::span<std::uint8_t const> read(std::size_t size)
  {
    try
    {
      auto ret = _sp.subspan(0, size);
      _sp = _sp.subspan(size);
      return ret;
    }
    catch (gsl::fail_fast const&)
    {
      throw Errors::Exception(
          Errc::TruncatedInput,
          "could not read " + std::to_string(size) + " bytes");
    }
  }

  std::size_t remaining_size() const noexcept
  {
    return _sp.size();
  }

  std::size_t read_varint()
  {
    auto const p = varint_read(_sp);
    _sp = p.second;
    return p.first;
  }

  bool eof() const
  {
    return _sp.empty();
  }

private:
  gsl::span<std::uint8_t const> _sp;
};
}
}
