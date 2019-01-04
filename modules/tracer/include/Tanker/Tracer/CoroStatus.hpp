#pragma once

namespace Tanker
{
namespace Tracer
{
enum CoroState
{
  Begin,
  Progress,
  End,
  Error,
};

enum CoroType
{
  Proc,
  Net,
  DB,
};
}
}
