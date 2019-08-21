#include <ctanker/base64.h>

#include <cppcodec/base64_rfc4648.hpp>
#include <tconcurrent/async.hpp>

#include <ctanker/async/private/CFuture.hpp>

uint64_t tanker_base64_encoded_size(uint64_t decoded_size)
{
  return cppcodec::base64_rfc4648::encoded_size(decoded_size);
}

uint64_t tanker_base64_decoded_max_size(uint64_t encoded_size)
{
  return cppcodec::base64_rfc4648::decoded_max_size(encoded_size);
}

void tanker_base64_encode(b64char* to, void const* from, uint64_t from_size)
{
  cppcodec::base64_rfc4648::encode(
      to,
      cppcodec::base64_rfc4648::encoded_size(from_size),
      static_cast<uint8_t const*>(from),
      from_size);
}

tanker_expected_t* tanker_base64_decode(void* to,
                                        uint64_t* to_size,
                                        b64char const* from,
                                        uint64_t from_size)
{
  return makeFuture(tc::sync([&] {
    auto const decoded_size = cppcodec::base64_rfc4648::decode(
        static_cast<uint8_t*>(to),
        cppcodec::base64_rfc4648::decoded_max_size(from_size),
        from,
        from_size);
    if (to_size)
      *to_size = decoded_size;
  }));
}
