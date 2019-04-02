#include <functional>
#include <optional.hpp>
#include <string>
#include <vector>

#include <cstdint>

#include <emscripten/bind.h>

#include <tconcurrent/coroutine.hpp>

namespace Tanker
{
namespace Emscripten
{
inline bool isNone(emscripten::val const& v)
{
  return v.isNull() || v.isUndefined();
}

template <typename T>
nonstd::optional<T> optionalFromValue(emscripten::val const& val,
                                      std::string const& key)
{
  if (Emscripten::isNone(val) || Emscripten::isNone(val[key]))
    return nonstd::nullopt;
  else
    return T{val[key].as<std::string>()};
}

template <typename T>
emscripten::val containerToJs(T const& cont)
{
  using emscripten::val;

  auto const Uint8Array = val::global("Uint8Array");
  val memory = val::module_property("buffer");
  return Uint8Array.new_(
      memory, reinterpret_cast<uintptr_t>(cont.data()), cont.size());
}

std::vector<uint8_t> copyToVector(emscripten::val const& typedArray);

template <typename T>
std::vector<T> copyToStringLikeVector(emscripten::val const& typedArray)
{
  using emscripten::val;

  auto const length = typedArray["length"].as<unsigned int>();
  std::vector<T> vec(length);

  for (unsigned int i = 0; i < length; ++i)
    vec[i] = T(typedArray[i].as<std::string>());
  return vec;
}

template <typename Sig>
emscripten::val toJsFunctionObject(std::function<Sig> functor)
{
  return emscripten::val(functor)["opcall"].template call<emscripten::val>(
      "bind", emscripten::val(functor));
}

tc::cotask<emscripten::val> jsPromiseToFuture(emscripten::val const& jspromise);

namespace detail
{
inline void resolveJsPromise(emscripten::val resolve, tc::future<void> fut)
{
  fut.get();
  resolve();
}

template <typename T>
inline void resolveJsPromise(emscripten::val resolve, tc::future<T> fut)
{
  resolve(fut.get());
}
}

template <typename T>
emscripten::val tcFutureToJsPromise(tc::future<T> fut)
{
  auto const Promise = emscripten::val::global("Promise");

  auto resolve = emscripten::val::undefined();
  auto reject = emscripten::val::undefined();
  auto const promise =
      Promise.new_(toJsFunctionObject<void(emscripten::val, emscripten::val)>(
          [&](emscripten::val presolve, emscripten::val preject) {
            resolve = presolve;
            reject = preject;
          }));

  fut.then([resolve, reject](auto fut) mutable {
    try
    {
      detail::resolveJsPromise(resolve, std::move(fut));
    }
    catch (std::exception const& e)
    {
      reject(typeid(e).name() + std::string(e.what()));
    }
    catch (...)
    {
      reject(std::string("unknown error"));
    }
  });

  return promise;
}
}
}
