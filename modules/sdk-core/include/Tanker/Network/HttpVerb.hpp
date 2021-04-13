#pragma once

namespace Tanker::Network
{
enum class HttpVerb
{
  Get,
  Post,
  Put,
  Patch,
  Delete,
};

inline char const* httpVerbToString(HttpVerb verb)
{
  switch (verb)
  {
  case HttpVerb::Get:
    return "GET";
  case HttpVerb::Post:
    return "POST";
  case HttpVerb::Put:
    return "PUT";
  case HttpVerb::Patch:
    return "PATCH";
  case HttpVerb::Delete:
    return "DELETE";
  }
  return "UNKNOWN";
}
}
