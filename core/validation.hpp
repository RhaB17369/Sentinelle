#pragma once

#include <string>

namespace sentinelle {
namespace validation {

/**
 * @brief Validation result with optional error message
 */
struct ValidationResult {
  bool valid;
  std::string error_message;

  ValidationResult(bool v = true, const std::string &msg = "")
      : valid(v), error_message(msg) {}

  operator bool() const { return valid; }
};

/**
 * @brief Validate URL according to RFC 3986
 * @param url URL string to validate
 * @return Validation result
 */
ValidationResult validate_url(const std::string &url);

/**
 * @brief Validate IPv4 address
 * @param ip IPv4 address string
 * @return Validation result
 */
ValidationResult validate_ipv4(const std::string &ip);

/**
 * @brief Validate IPv6 address
 * @param ip IPv6 address string
 * @return Validation result
 */
ValidationResult validate_ipv6(const std::string &ip);

/**
 * @brief Validate IP address (IPv4 or IPv6)
 * @param ip IP address string
 * @return Validation result
 */
ValidationResult validate_ip(const std::string &ip);

/**
 * @brief Validate domain name according to RFC 1035
 * @param domain Domain name string
 * @return Validation result
 */
ValidationResult validate_domain(const std::string &domain);

/**
 * @brief Validate email address
 * @param email Email address string
 * @return Validation result
 */
ValidationResult validate_email(const std::string &email);

/**
 * @brief Validate phone number (basic format check)
 * @param phone Phone number string
 * @return Validation result
 */
ValidationResult validate_phone(const std::string &phone);

/**
 * @brief Sanitize string for safe output (remove control characters)
 * @param input Input string
 * @return Sanitized string
 */
std::string sanitize_string(const std::string &input);

/**
 * @brief Check if string contains only alphanumeric and safe characters
 * @param input Input string
 * @param allowed_chars Additional allowed characters (e.g., ".-_")
 * @return true if safe, false otherwise
 */
bool is_safe_string(const std::string &input,
                    const std::string &allowed_chars = "");

/**
 * @brief Validate and normalize query input
 * @param query Query string
 * @param max_length Maximum allowed length
 * @return Validation result
 */
ValidationResult validate_query(const std::string &query,
                                size_t max_length = 1024);

} // namespace validation
} // namespace sentinelle
