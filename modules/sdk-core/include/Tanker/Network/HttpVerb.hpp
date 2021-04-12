#pragma once

namespace Tanker::Network
{
enum class HttpVerb
{
  get,
  post,
  put,
  patch,
  delete_,
};

inline char const* httpVerbToString(HttpVerb verb)
{
  switch (verb)
  {
  case HttpVerb::get:
    return "GET";
  case HttpVerb::post:
    return "POST";
  case HttpVerb::put:
    return "PUT";
  case HttpVerb::patch:
    return "PATCH";
  case HttpVerb::delete_:
    return "DELETE";
  }
  return "UNKNOWN";
}
}
