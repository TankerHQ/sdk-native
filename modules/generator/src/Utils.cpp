#include <Generator/Utils.hpp>

#include <cstddef>
#include <cstdint>
#include <vector>

namespace Tanker
{
namespace Generator
{
std::vector<uint8_t> make_random_bytes(std::size_t size)
{
  std::vector<uint8_t> buf(size);
  randombytes_buf(buf.data(), buf.size());
  return buf;
}
}
}
