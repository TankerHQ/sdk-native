#include <functional>
#include <vector>

#include <cstdint>

#include <emscripten/bind.h>

#include <tconcurrent/coroutine.hpp>

namespace Tanker
{
namespace Emscripten
{
template <typename T>
emscripten::val containerToJs(T const& cont)
{
  using emscripten::val;

  auto const Uint8Array = val::global("Uint8Array");
  val memory = val::module_property("buffer");
  return Uint8Array.new_(
      memory, reinterpret_cast<uintptr_t>(cont.data()), cont.size());
}

std::vector<uint8_t> copyToVector(const emscripten::val& typedArray);

template <typename Sig>
emscripten::val toJsFunctionObject(std::function<Sig> functor)
{
  return emscripten::val(functor)["opcall"].template call<emscripten::val>(
      "bind", emscripten::val(functor));
}

tc::cotask<emscripten::val> jsPromiseToFuture(emscripten::val const& jspromise);
}
}
