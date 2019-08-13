#include <Tanker/Emscripten/Error.hpp>

#include <Tanker/Emscripten/Helpers.hpp>

#include <emscripten/bind.h>

namespace Tanker
{
namespace Emscripten
{
emscripten::val currentExceptionToJs()
{
  try
  {
    throw;
  }
  catch (Tanker::Errors::Exception const& e)
  {
    return emscripten::val(
        EmError{static_cast<Errors::Errc>(
                    e.errorCode().default_error_condition().value()),
                e.what()});
  }
  catch (std::exception const& e)
  {
    return emscripten::val(
        EmError{Errors::Errc::InternalError,
                std::string(typeid(e).name()) + ": " + e.what()});
  }
  catch (...)
  {
    return emscripten::val(
        EmError{Errors::Errc::InternalError, "unknown error"});
  }
}
}
}

EMSCRIPTEN_BINDINGS(jserrors)
{
  emscripten::enum_<Tanker::Errors::Errc>("ErrorCode")
      .value("InvalidArgument", Tanker::Errors::Errc::InvalidArgument)
      .value("InternalError", Tanker::Errors::Errc::InternalError)
      .value("NetworkError", Tanker::Errors::Errc::NetworkError)
      .value("PreconditionFailed", Tanker::Errors::Errc::PreconditionFailed)
      .value("OperationCanceled", Tanker::Errors::Errc::OperationCanceled)
      .value("DecryptionFailed", Tanker::Errors::Errc::DecryptionFailed)
      .value("GroupTooBig", Tanker::Errors::Errc::GroupTooBig)
      .value("InvalidVerification", Tanker::Errors::Errc::InvalidVerification)
      .value("TooManyAttempts", Tanker::Errors::Errc::TooManyAttempts)
      .value("ExpiredVerification", Tanker::Errors::Errc::ExpiredVerification)
      .value("IOError", Tanker::Errors::Errc::IOError);

  static_assert(static_cast<int>(Tanker::Errors::Errc::Last) == 12,
                "Error code not mapped to emscripten");

  emscripten::value_object<Tanker::Emscripten::EmError>("EmError")
      .field("code", &Tanker::Emscripten::EmError::code)
      .field("message", &Tanker::Emscripten::EmError::message);
}
