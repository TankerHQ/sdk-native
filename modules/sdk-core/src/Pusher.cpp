#include <Tanker/Pusher.hpp>

#include <Tanker/Client.hpp>
#include <Tanker/Serialization/Serialization.hpp>

#include <cppcodec/base64_rfc4648.hpp>
#include <nlohmann/json.hpp>

namespace Tanker
{
Pusher::Pusher(Client* client) : _client(client)
{
}

tc::cotask<void> Pusher::pushBlock(Trustchain::GroupAction const& action)
{
  TC_AWAIT(_client->emit(
      "push block",
      cppcodec::base64_rfc4648::encode(Serialization::serialize(action))));
}

tc::cotask<void> Pusher::pushBlock(Trustchain::ClientEntry const& entry)
{
  TC_AWAIT(_client->emit(
      "push block",
      cppcodec::base64_rfc4648::encode(Serialization::serialize(entry))));
}

tc::cotask<void> Pusher::pushKeys(
    gsl::span<Trustchain::ClientEntry const> entries)
{
  std::vector<std::string> sb;
  sb.reserve(entries.size());
  for (auto const& entry : entries)
    sb.push_back(
        cppcodec::base64_rfc4648::encode(Serialization::serialize(entry)));
  TC_AWAIT(_client->emit("push keys", sb));
}

}
