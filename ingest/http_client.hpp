#pragma once

#include <map>
#include <memory>
#include <string>

namespace sentinelle {
namespace ingest {

/**
 * @brief HTTP response structure
 */
struct HttpResponse {
  int status_code;
  std::string body;
  std::map<std::string, std::string> headers;
  std::string error_message;

  bool is_success() const { return status_code >= 200 && status_code < 300; }
};

/**
 * @brief HTTP client configuration
 */
struct HttpConfig {
  long timeout_seconds = 30;
  long connect_timeout_seconds = 10;
  bool verify_ssl = true;
  std::string user_agent = "SENTINNELLE/1.0 (OSINT Intelligence Platform)";
  bool follow_redirects = true;
  long max_redirects = 5;
  size_t max_response_size = 10 * 1024 * 1024; // 10 MB
};

/**
 * @brief Secure HTTP/HTTPS client using libcurl
 */
class HttpClient {
public:
  explicit HttpClient(const HttpConfig &config = HttpConfig());
  ~HttpClient();

  // Prevent copying
  HttpClient(const HttpClient &) = delete;
  HttpClient &operator=(const HttpClient &) = delete;

  /**
   * @brief Perform GET request
   * @param url Target URL
   * @param headers Optional custom headers
   * @return HTTP response
   */
  HttpResponse get(const std::string &url,
                   const std::map<std::string, std::string> &headers = {});

  /**
   * @brief Perform POST request
   * @param url Target URL
   * @param body Request body
   * @param headers Optional custom headers
   * @return HTTP response
   */
  HttpResponse post(const std::string &url, const std::string &body,
                    const std::map<std::string, std::string> &headers = {});

  /**
   * @brief Set rate limiting (minimum delay between requests)
   * @param delay_ms Delay in milliseconds
   */
  void set_rate_limit(long delay_ms);

private:
  class Impl;
  std::unique_ptr<Impl> pimpl_;
};

} // namespace ingest
} // namespace sentinelle
