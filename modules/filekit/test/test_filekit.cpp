#include <Tanker/FileKit/FileKit.hpp>

#include <Tanker/AsyncCore.hpp>
#include <Tanker/Test/Functional/TrustchainFixture.hpp>

#include <Helpers/Buffers.hpp>
#include <Helpers/Errors.hpp>

#include <doctest.h>

using namespace Tanker;

TEST_CASE_FIXTURE(TrustchainFixture, "Test upload/download")
{
  auto alice = trustchain.makeUser();
  auto device = alice.makeDevice();
  auto core = TC_AWAIT(device.open());

  FileKit::FileKit storage(*core);
  FileKit::Metadata metadata;
  metadata.mime = "image/jpeg";
  metadata.name = "holidays.jpg";
  metadata.lastModified = std::chrono::milliseconds(128128);
  auto const buffer = make_buffer("this is a test");
  auto const resourceId = TC_AWAIT(storage.upload(buffer, metadata));
  auto const downloadResult = TC_AWAIT(storage.download(resourceId));
  CHECK(std::get<0>(downloadResult) == buffer);
  CHECK(std::get<1>(downloadResult).mime == metadata.mime);
  CHECK(std::get<1>(downloadResult).name == metadata.name);
  CHECK(std::get<1>(downloadResult).lastModified == metadata.lastModified);
}

TEST_CASE_FIXTURE(TrustchainFixture, "Test download 404")
{
  auto alice = trustchain.makeUser();
  auto device = alice.makeDevice();
  auto core = TC_AWAIT(device.open());

  FileKit::FileKit storage(*core);

  TANKER_CHECK_THROWS_WITH_CODE(
      TC_AWAIT(
          storage.download(make<Trustchain::ResourceId>("no such resource"))),
      Errors::Errc::InvalidArgument);
}
