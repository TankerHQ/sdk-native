#include <Tanker/Crypto/Format/Format.hpp>

#include <cppcodec/base64_rfc4648.hpp>
#include <cppcodec/base64_url.hpp>
#include <cppcodec/base64_url_unpadded.hpp>

namespace Tanker::Crypto::Format
{
std::string format_crypto_array(bool useSafe,
                                bool padded,
                                std::uint8_t const* beg,
                                std::size_t size)
{
  return useSafe ?
             (padded ? cppcodec::base64_url::encode<std::string>(beg, size) :
                       cppcodec::base64_url_unpadded::encode<std::string>(
                           beg, size)) :
             cppcodec::base64_rfc4648::encode<std::string>(beg, size);
}

}
