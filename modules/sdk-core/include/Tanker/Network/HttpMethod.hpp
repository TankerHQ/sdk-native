#pragma once

namespace Tanker::Network
{
enum class HttpMethod
{
  Get,
  Post,
  Put,
  Patch,
  Delete,
};

inline char const* httpMethodToString(HttpMethod method)
{
  switch (method)
  {
  case HttpMethod::Get:
    return "GET";
  case HttpMethod::Post:
    return "POST";
  case HttpMethod::Put:
    return "PUT";
  case HttpMethod::Patch:
    return "PATCH";
  case HttpMethod::Delete:
    return "DELETE";
  }
  return "UNKNOWN";
}
}
