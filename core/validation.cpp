#include "validation.hpp"
#include <arpa/inet.h>
#include <cctype>

namespace sentinelle {
namespace validation {

// URL validation (simplified RFC 3986)
ValidationResult validate_url(const std::string &url) {
  if (url.empty()) {
    return ValidationResult(false, "URL is empty");
  }

  if (url.length() > 2048) {
    return ValidationResult(false, "URL exceeds maximum length");
  }

  // Basic URL pattern: scheme://host[:port][/path][?query][#fragment]
  std::regex url_pattern(
      R"(^(https?|ftp)://)"                   // scheme
      R"(([a-zA-Z0-9.-]+|\[[0-9a-fA-F:]+\]))" // host (domain or IPv6)
      R"((:[0-9]{1,5})?)"                     // optional port
      R"((/[^\s]*)?$)"                        // optional path
  );

  if (!std::regex_match(url, url_pattern)) {
    return ValidationResult(false, "Invalid URL format");
  }

  return ValidationResult(true);
}

// IPv4 validation
ValidationResult validate_ipv4(const std::string &ip) {
  if (ip.empty()) {
    return ValidationResult(false, "IP address is empty");
  }

  struct sockaddr_in sa;
  int result = inet_pton(AF_INET, ip.c_str(), &(sa.sin_addr));

  if (result != 1) {
    return ValidationResult(false, "Invalid IPv4 address");
  }

  return ValidationResult(true);
}

// IPv6 validation
ValidationResult validate_ipv6(const std::string &ip) {
  if (ip.empty()) {
    return ValidationResult(false, "IP address is empty");
  }

  struct sockaddr_in6 sa;
  int result = inet_pton(AF_INET6, ip.c_str(), &(sa.sin6_addr));

  if (result != 1) {
    return ValidationResult(false, "Invalid IPv6 address");
  }

  return ValidationResult(true);
}

// IP validation (IPv4 or IPv6)
ValidationResult validate_ip(const std::string &ip) {
  auto ipv4_result = validate_ipv4(ip);
  if (ipv4_result.valid) {
    return ipv4_result;
  }

  auto ipv6_result = validate_ipv6(ip);
  if (ipv6_result.valid) {
    return ipv6_result;
  }

  return ValidationResult(false, "Invalid IP address (neither IPv4 nor IPv6)");
}

// Domain validation (RFC 1035)
ValidationResult validate_domain(const std::string &domain) {
  if (domain.empty()) {
    return ValidationResult(false, "Domain is empty");
  }

  if (domain.length() > 253) {
    return ValidationResult(false,
                            "Domain exceeds maximum length (253 characters)");
  }

  // Domain pattern: labels separated by dots
  // Each label: 1-63 chars, alphanumeric and hyphens, cannot start/end with
  // hyphen
  std::regex domain_pattern(
      R"(^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*)"
      R"([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$)");

  if (!std::regex_match(domain, domain_pattern)) {
    return ValidationResult(false, "Invalid domain format");
  }

  return ValidationResult(true);
}

// Email validation (simplified)
ValidationResult validate_email(const std::string &email) {
  if (email.empty()) {
    return ValidationResult(false, "Email is empty");
  }

  if (email.length() > 254) {
    return ValidationResult(false, "Email exceeds maximum length");
  }

  // Simplified email pattern
  std::regex email_pattern(
      R"(^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$)");

  if (!std::regex_match(email, email_pattern)) {
    return ValidationResult(false, "Invalid email format");
  }

  return ValidationResult(true);
}

// Phone validation (basic format check)
ValidationResult validate_phone(const std::string &phone) {
  if (phone.empty()) {
    return ValidationResult(false, "Phone number is empty");
  }

  if (phone.length() > 20) {
    return ValidationResult(false, "Phone number exceeds maximum length");
  }

  // Allow digits, spaces, hyphens, parentheses, and + prefix
  std::regex phone_pattern(R"(^\+?[0-9\s\-\(\)]{7,20}$)");

  if (!std::regex_match(phone, phone_pattern)) {
    return ValidationResult(false, "Invalid phone number format");
  }

  return ValidationResult(true);
}

// String sanitization
std::string sanitize_string(const std::string &input) {
  std::string output;
  output.reserve(input.length());

  for (char c : input) {
    // Remove control characters except newline and tab
    if (std::iscntrl(static_cast<unsigned char>(c))) {
      if (c == '\n' || c == '\t') {
        output += c;
      }
    } else {
      output += c;
    }
  }

  return output;
}

// Safe string check
bool is_safe_string(const std::string &input,
                    const std::string &allowed_chars) {
  for (char c : input) {
    bool is_alnum = std::isalnum(static_cast<unsigned char>(c));
    bool is_allowed = allowed_chars.find(c) != std::string::npos;

    if (!is_alnum && !is_allowed) {
      return false;
    }
  }

  return true;
}

// Query validation
ValidationResult validate_query(const std::string &query, size_t max_length) {
  if (query.empty()) {
    return ValidationResult(false, "Query is empty");
  }

  if (query.length() > max_length) {
    return ValidationResult(false, "Query exceeds maximum length");
  }

  // Check for null bytes
  if (query.find('\0') != std::string::npos) {
    return ValidationResult(false, "Query contains null bytes");
  }

  return ValidationResult(true);
}

} // namespace validation
} // namespace sentinelle
