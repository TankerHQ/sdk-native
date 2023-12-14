#pragma once

#include <Tanker/Functional/Device.hpp>
#include <Tanker/Functional/Trustchain.hpp>
#include <Tanker/Functional/User.hpp>

#include <Helpers/Await.hpp>

#include <range/v3/range/conversion.hpp>
#include <range/v3/view/concat.hpp>
#include <range/v3/view/transform.hpp>

namespace Tanker::Functional
{
class UserSession
{
public:
  Functional::Trustchain& trustchain;
  Functional::User user;
  Functional::Device device;
  Functional::AsyncCorePtr session;

  UserSession(Functional::Trustchain& t)
    : trustchain(t), user(trustchain.makeUser()), device(user.makeDevice()), session(AWAIT(device.open()))
  {
  }

  UserSession(Functional::Trustchain& t,
              Functional::User user,
              Functional::Device device,
              Functional::AsyncCorePtr session)
    : trustchain(t), user(std::move(user)), device(std::move(device)), session(std::move(session))
  {
  }

  virtual ~UserSession() = default;

  virtual SPublicIdentity spublicIdentity() const
  {
    return user.spublicIdentity();
  }

  SPublicIdentity userSPublicIdentity() const
  {
    return user.spublicIdentity();
  }
};

class ProvisionalUserSession : public UserSession
{
public:
  Functional::AppProvisionalUser provisionalUser;

  ProvisionalUserSession(Functional::Trustchain& t, ProvisionalUserType type = ProvisionalUserType::Email)
    : UserSession(t), provisionalUser(t.makeProvisionalUser(type))
  {
  }

  SPublicIdentity spublicIdentity() const
  {
    return provisionalUser.publicIdentity;
  }

  tc::cotask<void> attach()
  {
    TC_AWAIT(trustchain.attachProvisionalIdentity(*session, provisionalUser));
  }
};

template <typename... T>
std::vector<SPublicIdentity> getPublicIdentities(T const&... userSessions)
{
  return ranges::views::concat((userSessions | ranges::views::transform(&UserSession::spublicIdentity))...) |
         ranges::to<std::vector>;
}

inline tc::cotask<void> attachProvisionalIdentities(gsl::span<ProvisionalUserSession> userSessions)
{
  for (auto& p : userSessions)
    TC_AWAIT(p.attach());
}

template <typename T>
std::vector<T> generate(Functional::Trustchain& trustchain, int nb)
{
  std::vector<T> users;
  for (int i = 0; i < nb; ++i)
    users.push_back(T(trustchain));
  return users;
}

template <typename T>
std::vector<T> generate(Functional::Trustchain& trustchain, int nbEmail, int nbPhoneNumber)
{
  std::vector<T> users;
  for (int i = 0; i < nbEmail; ++i)
    users.push_back(T(trustchain, ProvisionalUserType::Email));
  for (int i = 0; i < nbPhoneNumber; ++i)
    users.push_back(T(trustchain, ProvisionalUserType::PhoneNumber));
  return users;
}
}
