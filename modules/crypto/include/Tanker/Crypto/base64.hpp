#pragma once

#include <cppcodec/base64_url.hpp>
#include <cppcodec/base64_url_unpadded.hpp>

namespace Tanker
{
using safeBase64Unpadded = cppcodec::base64_url_unpadded;
using safeBase64 = cppcodec::base64_url;
}
