#pragma once

#include <Tanker/Client.hpp>
#include <Tanker/Trustchain/ResourceId.hpp>

#include <nlohmann/json_fwd.hpp>

#include <map>
#include <string>

namespace Tanker
{
namespace CloudStorage
{
struct UploadTicket
{
  std::string url;
  std::map<std::string, std::string> headers;
  std::string service;
};
void from_json(nlohmann::json const& json, UploadTicket& uploadTicket);

struct DownloadTicket
{
  std::string url;
  std::string service;
};
void from_json(nlohmann::json const& json, DownloadTicket& downloadTicket);

tc::cotask<UploadTicket> getFileUploadTicket(
    Client& client, Trustchain::ResourceId const& resourceId, uint64_t length);
tc::cotask<DownloadTicket> getFileDownloadTicket(
    Client& client, Trustchain::ResourceId const& resourceId);
}
}
