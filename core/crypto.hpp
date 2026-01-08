#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace sentinelle {
namespace crypto {

/**
 * @brief RAII wrapper for secure memory that zeros on destruction
 */
class SecureBuffer {
public:
  explicit SecureBuffer(size_t size);
  ~SecureBuffer();

  // Prevent copying
  SecureBuffer(const SecureBuffer &) = delete;
  SecureBuffer &operator=(const SecureBuffer &) = delete;

  // Allow moving
  SecureBuffer(SecureBuffer &&other) noexcept;
  SecureBuffer &operator=(SecureBuffer &&other) noexcept;

  uint8_t *data() { return data_; }
  const uint8_t *data() const { return data_; }
  size_t size() const { return size_; }

private:
  uint8_t *data_;
  size_t size_;
  void zero();
};

/**
 * @brief Compute SHA-256 hash of input data
 * @param data Input data to hash
 * @param output Output buffer (must be at least 32 bytes)
 * @return true on success, false on failure
 */
bool sha256(const std::vector<uint8_t> &data, uint8_t *output);

/**
 * @brief Compute SHA-256 hash of string
 * @param data Input string
 * @return Hex-encoded hash string, or empty string on failure
 */
std::string sha256_hex(const std::string &data);

/**
 * @brief Compute SHA-512 hash of input data
 * @param data Input data to hash
 * @param output Output buffer (must be at least 64 bytes)
 * @return true on success, false on failure
 */
bool sha512(const std::vector<uint8_t> &data, uint8_t *output);

/**
 * @brief Compute SHA-512 hash of string
 * @param data Input string
 * @return Hex-encoded hash string, or empty string on failure
 */
std::string sha512_hex(const std::string &data);

/**
 * @brief Compute HMAC-SHA256
 * @param key HMAC key
 * @param data Data to authenticate
 * @param output Output buffer (must be at least 32 bytes)
 * @return true on success, false on failure
 */
bool hmac_sha256(const std::vector<uint8_t> &key,
                 const std::vector<uint8_t> &data, uint8_t *output);

/**
 * @brief Constant-time comparison of two buffers
 * @param a First buffer
 * @param b Second buffer
 * @return true if buffers are equal, false otherwise
 */
bool constant_time_compare(const std::vector<uint8_t> &a,
                           const std::vector<uint8_t> &b);

/**
 * @brief Convert bytes to hex string
 * @param data Input bytes
 * @return Hex-encoded string
 */
std::string bytes_to_hex(const uint8_t *data, size_t len);

/**
 * @brief Convert hex string to bytes
 * @param hex Hex-encoded string
 * @return Decoded bytes, or empty vector on failure
 */
std::vector<uint8_t> hex_to_bytes(const std::string &hex);

} // namespace crypto
} // namespace sentinelle
