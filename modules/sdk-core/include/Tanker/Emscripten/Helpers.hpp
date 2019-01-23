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
emscripten::val containerToJs(T const& vec);

std::vector<uint8_t> copyToVector(const emscripten::val& typedArray);

template <typename Sig>
emscripten::val toJsFunctor(std::function<Sig> functor);

tc::cotask<emscripten::val> jsPromiseToFuture(emscripten::val const& jspromise);
}
}
