#include "crypto.hpp"
#include <cstring>
#include <iomanip>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <sstream>
#include <stdexcept>

namespace sentinelle {
namespace crypto {

// SecureBuffer implementation
SecureBuffer::SecureBuffer(size_t size) : data_(nullptr), size_(size) {
  if (size > 0) {
    data_ = new uint8_t[size];
    std::memset(data_, 0, size);
  }
}

SecureBuffer::~SecureBuffer() { zero(); }

SecureBuffer::SecureBuffer(SecureBuffer &&other) noexcept
    : data_(other.data_), size_(other.size_) {
  other.data_ = nullptr;
  other.size_ = 0;
}

SecureBuffer &SecureBuffer::operator=(SecureBuffer &&other) noexcept {
  if (this != &other) {
    zero();
    data_ = other.data_;
    size_ = other.size_;
    other.data_ = nullptr;
    other.size_ = 0;
  }
  return *this;
}

void SecureBuffer::zero() {
  if (data_) {
    // Explicit zeroization to prevent compiler optimization
    OPENSSL_cleanse(data_, size_);
    delete[] data_;
    data_ = nullptr;
    size_ = 0;
  }
}

// SHA-256 implementation
bool sha256(const std::vector<uint8_t> &data, uint8_t *output) {
  if (!output)
    return false;

  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  if (!ctx)
    return false;

  bool success = false;
  do {
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1)
      break;
    if (EVP_DigestUpdate(ctx, data.data(), data.size()) != 1)
      break;

    unsigned int len = 0;
    if (EVP_DigestFinal_ex(ctx, output, &len) != 1)
      break;
    if (len != SHA256_DIGEST_LENGTH)
      break;

    success = true;
  } while (false);

  EVP_MD_CTX_free(ctx);
  return success;
}

std::string sha256_hex(const std::string &data) {
  std::vector<uint8_t> input(data.begin(), data.end());
  uint8_t hash[SHA256_DIGEST_LENGTH];

  if (!sha256(input, hash)) {
    return "";
  }

  return bytes_to_hex(hash, SHA256_DIGEST_LENGTH);
}

// SHA-512 implementation
bool sha512(const std::vector<uint8_t> &data, uint8_t *output) {
  if (!output)
    return false;

  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  if (!ctx)
    return false;

  bool success = false;
  do {
    if (EVP_DigestInit_ex(ctx, EVP_sha512(), nullptr) != 1)
      break;
    if (EVP_DigestUpdate(ctx, data.data(), data.size()) != 1)
      break;

    unsigned int len = 0;
    if (EVP_DigestFinal_ex(ctx, output, &len) != 1)
      break;
    if (len != SHA512_DIGEST_LENGTH)
      break;

    success = true;
  } while (false);

  EVP_MD_CTX_free(ctx);
  return success;
}

std::string sha512_hex(const std::string &data) {
  std::vector<uint8_t> input(data.begin(), data.end());
  uint8_t hash[SHA512_DIGEST_LENGTH];

  if (!sha512(input, hash)) {
    return "";
  }

  return bytes_to_hex(hash, SHA512_DIGEST_LENGTH);
}

// HMAC-SHA256 implementation
bool hmac_sha256(const std::vector<uint8_t> &key,
                 const std::vector<uint8_t> &data, uint8_t *output) {
  if (!output)
    return false;

  unsigned int len = 0;
  uint8_t *result = HMAC(EVP_sha256(), key.data(), key.size(), data.data(),
                         data.size(), output, &len);

  return (result != nullptr && len == SHA256_DIGEST_LENGTH);
}

// Constant-time comparison
bool constant_time_compare(const std::vector<uint8_t> &a,
                           const std::vector<uint8_t> &b) {
  if (a.size() != b.size())
    return false;

  return CRYPTO_memcmp(a.data(), b.data(), a.size()) == 0;
}

// Hex conversion utilities
std::string bytes_to_hex(const uint8_t *data, size_t len) {
  std::ostringstream oss;
  oss << std::hex << std::setfill('0');
  for (size_t i = 0; i < len; ++i) {
    oss << std::setw(2) << static_cast<unsigned int>(data[i]);
  }
  return oss.str();
}

std::vector<uint8_t> hex_to_bytes(const std::string &hex) {
  if (hex.length() % 2 != 0)
    return {};

  std::vector<uint8_t> bytes;
  bytes.reserve(hex.length() / 2);

  for (size_t i = 0; i < hex.length(); i += 2) {
    std::string byte_str = hex.substr(i, 2);
    try {
      uint8_t byte = static_cast<uint8_t>(std::stoi(byte_str, nullptr, 16));
      bytes.push_back(byte);
    } catch (...) {
      return {};
    }
  }

  return bytes;
}

} // namespace crypto
} // namespace sentinelle
