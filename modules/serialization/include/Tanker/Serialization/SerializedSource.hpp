#pragma once

#include <cstdint>

#include <gsl-lite.hpp>

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
    auto ret = _sp.subspan(0, size);
    _sp = _sp.subspan(size);
    return ret;
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
