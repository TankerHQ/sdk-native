#include <Tanker/Emscripten/Error.hpp>

#include <Tanker/Emscripten/Helpers.hpp>

#include <Tanker/Error.hpp>
#include <Tanker/RecipientNotFound.hpp>
#include <Tanker/ResourceKeyNotFound.hpp>
#include <Tanker/UserNotFound.hpp>

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
  catch (Tanker::Error::ResourceKeyNotFound const& e)
  {
    auto jerr =
        emscripten::val(EmError{Error::Code::ResourceKeyNotFound, e.what()});
    jerr.set("resourceId", containerToJs(e.resourceId()));
    return jerr;
  }
  catch (Tanker::Error::RecipientNotFound const& e)
  {
    auto jerr =
        emscripten::val(EmError{Error::Code::RecipientNotFound, e.what()});
    auto jidentities = emscripten::val::array();
    for (auto const& i : e.publicIdentities())
      jidentities.call<void>("push", i.string());
    for (auto const& i : e.groupIds())
      jidentities.call<void>("push", cppcodec::base64_rfc4648::encode(i));
    jerr.set("recipientIds", jidentities);
    return jerr;
  }
  catch (Tanker::Error::UserNotFound const& e)
  {
    auto jerr = emscripten::val(EmError{Error::Code::UserNotFound, e.what()});
    auto jidentities = emscripten::val::array();
    for (auto const& i : e.publicIdentities())
      jidentities.call<void>("push", i.string());
    jerr.set("recipientIds", jidentities);
    return jerr;
  }
  catch (Crypto::InvalidKeySize const& e)
  {
    return emscripten::val(EmError{Error::Code::InvalidArgument, e.what()});
  }
  catch (cppcodec::parse_error const& e)
  {
    return emscripten::val(
        EmError{Error::Code::InvalidArgument,
                fmt::format(TFMT("invalid base64: {:s}"), e.what())});
  }
  catch (cppcodec::invalid_output_length const& e)
  {
    return emscripten::val(
        EmError{Error::Code::InvalidArgument,
                fmt::format(TFMT("invalid base64 length: {:s}"), e.what())});
  }
  catch (Tanker::Error::Exception const& e)
  {
    return emscripten::val(EmError{e.code(), e.message()});
  }
  catch (std::invalid_argument const& e)
  {
    return emscripten::val(
        EmError{Error::Code::InvalidArgument,
                std::string(typeid(e).name()) + ": " + e.what()});
  }
  catch (std::exception const& e)
  {
    return emscripten::val(EmError{
        Error::Code::Other, std::string(typeid(e).name()) + ": " + e.what()});
  }
  catch (...)
  {
    return emscripten::val(EmError{Error::Code::Other, "unknown error"});
  }
}
}
}

EMSCRIPTEN_BINDINGS(jserrors)
{
  emscripten::enum_<Tanker::Error::Code>("ErrorCode")
      .value("NoError", Tanker::Error::Code::NoError)
      .value("Other", Tanker::Error::Code::Other)
      .value("InvalidTankerStatus", Tanker::Error::Code::InvalidTankerStatus)
      .value("ServerError", Tanker::Error::Code::ServerError)
      .value("InvalidArgument", Tanker::Error::Code::InvalidArgument)
      .value("ResourceKeyNotFound", Tanker::Error::Code::ResourceKeyNotFound)
      .value("UserNotFound", Tanker::Error::Code::UserNotFound)
      .value("DecryptFailed", Tanker::Error::Code::DecryptFailed)
      .value("InvalidVerificationKey", Tanker::Error::Code::InvalidVerificationKey)
      .value("InternalError", Tanker::Error::Code::InternalError)
      .value("InvalidUnlockPassword",
             Tanker::Error::Code::InvalidUnlockPassword)
      .value("InvalidVerificationCode",
             Tanker::Error::Code::InvalidVerificationCode)
      .value("VerificationKeyAlreadyExists",
             Tanker::Error::Code::VerificationKeyAlreadyExists)
      .value("MaxVerificationAttemptsReached",
             Tanker::Error::Code::MaxVerificationAttemptsReached)
      .value("InvalidGroupSize", Tanker::Error::Code::InvalidGroupSize)
      .value("RecipientNotFound", Tanker::Error::Code::RecipientNotFound)
      .value("GroupNotFound", Tanker::Error::Code::GroupNotFound)
      .value("DeviceNotFound", Tanker::Error::Code::DeviceNotFound)
      .value("IdentityAlreadyRegistered",
             Tanker::Error::Code::IdentityAlreadyRegistered)
      .value("OperationCanceled", Tanker::Error::Code::OperationCanceled)
      .value("NothingToClaim", Tanker::Error::Code::NothingToClaim);

  static_assert(static_cast<int>(Tanker::Error::Code::Last) == 21,
                "Error code not mapped to emscripten");

  emscripten::value_object<Tanker::Emscripten::EmError>("EmError")
      .field("code", &Tanker::Emscripten::EmError::code)
      .field("message", &Tanker::Emscripten::EmError::message);
}
