#include <Tanker/Streams/DecryptionStreamV11.hpp>

#include <Tanker/Crypto/SubkeySeed.hpp>
#include <Tanker/Encryptor/v11.hpp>

using namespace Tanker::Crypto;

namespace Tanker::Streams
{
DecryptionStreamV11::DecryptionStreamV11(InputSource cb, TransparentSessionHeader header, Crypto::SymmetricKey key)
  : DecryptionStream(std::move(cb), header, key),
    _associatedData(EncryptorV11::makeMacData(header.resourceId().sessionId(),
                                              SubkeySeed{header.resourceId().individualResourceId()},
                                              header.encryptedChunkSize())),
    _onlyPaddingLeft(false)
{
}

tc::cotask<void> DecryptionStreamV11::decryptChunk()
{
  auto const input = TC_AWAIT(readInputSource(_header.encryptedChunkSize()));
  if (input.size() < EncryptorV11::chunkOverhead)
    throw Exception(make_error_code(Errors::Errc::DecryptionFailed), "truncated buffer: missing chunk metadata");

  auto const sessId = _header.resourceId().sessionId();
  AeadIv seedIv{};
  std::copy(sessId.begin(), sessId.end(), seedIv.begin());
  auto const iv = deriveIv(seedIv, _chunkIndex);
  ++_chunkIndex;
  auto output = prepareWrite(decryptedSize(input.size()));
  decryptAead(_key, iv, output, input, _associatedData);

  auto const paddingSize = Serialization::deserialize<uint32_t>(output.subspan(0, EncryptorV11::paddingSizeSize));
  if (input.size() < EncryptorV11::chunkOverhead + paddingSize)
    throw Exception(make_error_code(Errors::Errc::DecryptionFailed), "invalid padding size value");
  auto const unpadded = output.subspan(EncryptorV11::paddingSizeSize + paddingSize);

  if (_onlyPaddingLeft && unpadded.size() != 0)
    throw Errors::formatEx(Errors::Errc::DecryptionFailed, "invalid padding");
  else if (paddingSize)
    _onlyPaddingLeft = true;

  std::memmove(output.data(), unpadded.data(), unpadded.size());
  shrinkOutput(unpadded.size());

  if (isInputEndOfStream())
    endOutputStream();
}

tc::cotask<std::optional<SymmetricKey>> DecryptionStreamV11::tryGetKey(ResourceKeyFinder const& finder,
                                                                       TransparentSessionHeader const& header)
{
  auto const resId = header.resourceId().individualResourceId();
  if (auto key = TC_AWAIT(finder(header.resourceId().sessionId())); key)
    TC_RETURN(EncryptorV11::deriveSubkey(*key, SubkeySeed{resId}));
  TC_RETURN(TC_AWAIT(finder(resId)));
}
}
