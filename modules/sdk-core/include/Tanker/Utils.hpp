#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Errors/Exception.hpp>
#include <Tanker/Trustchain/GroupId.hpp>
#include <Tanker/Types/SGroupId.hpp>

#include <mgs/base64.hpp>
#include <mgs/codecs/concepts/codec.hpp>

#include <range/v3/range/conversion.hpp>
#include <range/v3/view/transform.hpp>

#include <algorithm>
#include <type_traits>
#include <vector>

namespace Tanker
{
template <typename T, typename String>
T base64DecodeArgument(String const& b64, std::string const& argName)
{
  using namespace Tanker::Errors;

  try
  {
    return mgs::base64::decode<T>(b64);
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

template <typename Codec = mgs::base64,
          typename T,
          typename = std::enable_if_t<Crypto::IsCryptographicType<T>::value &&
                                      mgs::codecs::is_codec<Codec>::value>>
std::vector<std::string> encodeCryptoTypes(gsl::span<T> cryptoTypes)
{
  std::vector<std::string> ret;
  ret.reserve(cryptoTypes.size());
  for (auto const& elem : cryptoTypes)
    ret.push_back(Codec::template encode(elem));
  return ret;
}
}
