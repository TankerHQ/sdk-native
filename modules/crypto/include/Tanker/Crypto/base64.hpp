#pragma once

#include <cppcodec/base64_rfc4648.hpp>
#include <cppcodec/base64_url.hpp>
#include <cppcodec/base64_url_unpadded.hpp>

namespace Tanker
{
using base64 = cppcodec::base64_rfc4648;
using safeBase64Unpadded = cppcodec::base64_url_unpadded;
using safeBase64 = cppcodec::base64_url;
}
