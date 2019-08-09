#include <ctanker/fakeauthentication.h>

#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Errors/Exception.hpp>
#include <Tanker/FakeAuthentication/FakeAuthentication.hpp>
#include <ctanker/async/CFuture.hpp>
#include <optional.hpp>

#include <cstring>

namespace
{
template <typename Str = char*>
Str duplicateString(std::string const& str)
{
  auto ret = static_cast<Str>(std::malloc(str.size() + 1));
  return std::strcpy(ret, str.c_str());
}

template <typename T = std::string>
inline auto to_vector(char const* const* tab, uint64_t size)
{
  std::vector<T> res;
  res.reserve(size);
  std::transform(
      tab, std::next(tab, size), std::back_inserter(res), [](auto&& elem) {
        return T{elem};
      });
  return res;
}
}

using Tanker::Errors::Errc;
using Tanker::Errors::Exception;
using Tanker::FakeAuthentication::FakeAuthentication;

tanker_expected_t* tanker_fake_authentication_create(
    tanker_fake_authentication_options_t const* options)
{
  return makeFuture(tc::sync([&] {
    if (options == nullptr || options->app_id == nullptr)
    {
      throw Exception(make_error_code(Errc::InvalidArgument),
                      "options is null");
    }
    auto fakeAuth = new FakeAuthentication(options->app_id, options->url);
    return static_cast<void*>(fakeAuth);
  }));
}

tanker_future_t* tanker_fake_authentication_destroy(
    tanker_fake_authentication_t* fake_auth)
{
  return makeFuture(tc::async([fakeAuth = reinterpret_cast<FakeAuthentication*>(
                                   fake_auth)] { delete fakeAuth; }));
}

tanker_future_t* tanker_fake_authentication_get_private_identity(
    tanker_fake_authentication_t* fake_auth, char const* cemail)
{
  auto const fakeAuth = reinterpret_cast<FakeAuthentication*>(fake_auth);
  nonstd::optional<std::string> email;
  if (cemail != nullptr)
    email = std::string(cemail);

  return makeFuture(tc::async_resumable([=]() -> tc::cotask<void*> {
    auto const privateIdentity = TC_AWAIT(fakeAuth->getPrivateIdentity(email));
    auto const private_identity =
        new tanker_fake_authentication_private_identity_t;
    private_identity->permanent_identity =
        duplicateString(privateIdentity.permanentIdentity);
    private_identity->provisional_identity =
        privateIdentity.provisionalIdentity.has_value() ?
            duplicateString(privateIdentity.provisionalIdentity.value()) :
            nullptr;
    TC_RETURN(static_cast<void*>(private_identity));
  }));
}

tanker_future_t* tanker_fake_authentication_get_public_identities(
    tanker_fake_authentication_t* fake_auth,
    char const* const* cemails,
    uint64_t nb_emails)
{
  auto const fakeAuth = reinterpret_cast<FakeAuthentication*>(fake_auth);
  auto const emails = to_vector(cemails, nb_emails);
  return makeFuture(tc::async_resumable([=]() -> tc::cotask<void*> {
    auto const publicIdentities =
        TC_AWAIT(fakeAuth->getPublicIdentities(emails));
    auto public_identities = new tanker_fake_authentication_public_identities_t;
    auto ids = new char*[emails.size()];
    auto id = ids;
    for (auto const& email : emails)
    {
      *id = duplicateString(email);
      ++id;
    }
    public_identities->public_identities = ids;
    public_identities->nb_public_identities = emails.size();
    TC_RETURN(static_cast<void*>(public_identities));
  }));
}

void tanker_fake_authentication_destroy_private_identity(
    tanker_fake_authentication_private_identity_t* private_identity)
{
  if (private_identity)
  {
    std::free(const_cast<char*>(private_identity->provisional_identity));
    std::free(const_cast<char*>(private_identity->permanent_identity));
    delete private_identity;
  }
}

void tanker_fake_authentication_destroy_public_identities(
    tanker_fake_authentication_public_identities_t* public_identities)
{
  if (public_identities)
  {
    for (auto i = 0u; i < public_identities->nb_public_identities; ++i)
      std::free(const_cast<char*>(public_identities->public_identities[i]));
    delete public_identities->public_identities;
    delete public_identities;
  }
}
