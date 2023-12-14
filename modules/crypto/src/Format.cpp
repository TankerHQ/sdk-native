#include <Tanker/Crypto/Format/Format.hpp>

#include <mgs/base64.hpp>
#include <mgs/base64url.hpp>

namespace Tanker::Crypto::Format
{
std::string format_crypto_array(bool useSafe, bool padded, std::uint8_t const* beg, std::size_t size)
{
  return useSafe ? (padded ? mgs::base64url::encode<std::string>(beg, beg + size) :
                             mgs::base64url_nopad::encode<std::string>(beg, beg + size)) :
                   mgs::base64::encode<std::string>(beg, beg + size);
}

}
