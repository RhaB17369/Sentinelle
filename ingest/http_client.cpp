#include "http_client.hpp"
#include "../core/validation.hpp"
#include <chrono>
#include <curl/curl.h>
#include <stdexcept>
#include <thread>

namespace sentinelle {
namespace ingest {

// Callback for writing response data
static size_t write_callback(void *contents, size_t size, size_t nmemb,
                             void *userp) {
  size_t total_size = size * nmemb;
  std::string *response = static_cast<std::string *>(userp);

  // Check max size to prevent memory exhaustion
  if (response->size() + total_size > 10 * 1024 * 1024) {
    return 0; // Abort transfer
  }

  response->append(static_cast<char *>(contents), total_size);
  return total_size;
}

// Callback for reading headers
static size_t header_callback(char *buffer, size_t size, size_t nitems,
                              void *userdata) {
  size_t total_size = size * nitems;
  auto *headers = static_cast<std::map<std::string, std::string> *>(userdata);

  std::string header(buffer, total_size);
  size_t colon_pos = header.find(':');

  if (colon_pos != std::string::npos) {
    std::string key = header.substr(0, colon_pos);
    std::string value = header.substr(colon_pos + 1);

    // Trim whitespace
    value.erase(0, value.find_first_not_of(" \t\r\n"));
    value.erase(value.find_last_not_of(" \t\r\n") + 1);

    (*headers)[key] = value;
  }

  return total_size;
}

// Implementation class
class HttpClient::Impl {
public:
  HttpConfig config;
  CURL *curl;
  std::chrono::steady_clock::time_point last_request_time;
  long rate_limit_ms = 0;

  Impl(const HttpConfig &cfg) : config(cfg), curl(nullptr) {
    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();
    if (!curl) {
      throw std::runtime_error("Failed to initialize CURL");
    }
  }

  ~Impl() {
    if (curl) {
      curl_easy_cleanup(curl);
    }
    curl_global_cleanup();
  }

  void enforce_rate_limit() {
    if (rate_limit_ms > 0) {
      auto now = std::chrono::steady_clock::now();
      auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                         now - last_request_time)
                         .count();

      if (elapsed < rate_limit_ms) {
        std::this_thread::sleep_for(
            std::chrono::milliseconds(rate_limit_ms - elapsed));
      }

      last_request_time = std::chrono::steady_clock::now();
    }
  }

  HttpResponse perform_request(
      const std::string &url, const std::string &method,
      const std::string &body = "",
      const std::map<std::string, std::string> &custom_headers = {}) {
    HttpResponse response;
    response.status_code = 0;

    // Validate URL
    auto validation = validation::validate_url(url);
    if (!validation.valid) {
      response.error_message = "Invalid URL: " + validation.error_message;
      return response;
    }

    // Enforce rate limiting
    enforce_rate_limit();

    // Reset curl handle
    curl_easy_reset(curl);

    // Set URL
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());

    // Set method
    if (method == "POST") {
      curl_easy_setopt(curl, CURLOPT_POST, 1L);
      curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());
      curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, body.length());
    }

    // Set timeouts
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, config.timeout_seconds);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT,
                     config.connect_timeout_seconds);

    // SSL/TLS settings
    if (config.verify_ssl) {
      curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
      curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    } else {
      curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
      curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    }

    // Force TLS 1.2+
    curl_easy_setopt(curl, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2);

    // Follow redirects
    if (config.follow_redirects) {
      curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
      curl_easy_setopt(curl, CURLOPT_MAXREDIRS, config.max_redirects);
    }

    // Set user agent
    curl_easy_setopt(curl, CURLOPT_USERAGENT, config.user_agent.c_str());

    // Set custom headers
    struct curl_slist *headers_list = nullptr;
    for (const auto &[key, value] : custom_headers) {
      std::string header = key + ": " + value;
      headers_list = curl_slist_append(headers_list, header.c_str());
    }
    if (headers_list) {
      curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers_list);
    }

    // Set callbacks
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response.body);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, header_callback);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, &response.headers);

    // Perform request
    CURLcode res = curl_easy_perform(curl);

    // Clean up headers
    if (headers_list) {
      curl_slist_free_all(headers_list);
    }

    // Check for errors
    if (res != CURLE_OK) {
      response.error_message = curl_easy_strerror(res);
      return response;
    }

    // Get status code
    long status_code;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status_code);
    response.status_code = static_cast<int>(status_code);

    return response;
  }
};

// HttpClient implementation
HttpClient::HttpClient(const HttpConfig &config)
    : pimpl_(std::make_unique<Impl>(config)) {}

HttpClient::~HttpClient() = default;

HttpResponse
HttpClient::get(const std::string &url,
                const std::map<std::string, std::string> &headers) {
  return pimpl_->perform_request(url, "GET", "", headers);
}

HttpResponse
HttpClient::post(const std::string &url, const std::string &body,
                 const std::map<std::string, std::string> &headers) {
  return pimpl_->perform_request(url, "POST", body, headers);
}

void HttpClient::set_rate_limit(long delay_ms) {
  pimpl_->rate_limit_ms = delay_ms;
}

} // namespace ingest
} // namespace sentinelle
