#include "../core/crypto.hpp"
#include "../core/validation.hpp"
#include "../ingest/http_client.hpp"
#include "../ingest/parsers.hpp"
#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

namespace py = pybind11;
using namespace sentinelle;

PYBIND11_MODULE(sentinelle_core, m) {
  m.doc() = "SENTINNELLE C++ core module";

  // Crypto module
  py::module crypto_m = m.def_submodule("crypto", "Cryptographic operations");

  crypto_m.def("sha256_hex", &crypto::sha256_hex,
               "Compute SHA-256 hash and return hex string", py::arg("data"));

  crypto_m.def("sha512_hex", &crypto::sha512_hex,
               "Compute SHA-512 hash and return hex string", py::arg("data"));

  crypto_m.def(
      "bytes_to_hex",
      [](const std::vector<uint8_t> &data) {
        return crypto::bytes_to_hex(data.data(), data.size());
      },
      "Convert bytes to hex string", py::arg("data"));

  crypto_m.def("hex_to_bytes", &crypto::hex_to_bytes,
               "Convert hex string to bytes", py::arg("hex"));

  // Validation module
  py::module validation_m = m.def_submodule("validation", "Input validation");

  py::class_<validation::ValidationResult>(validation_m, "ValidationResult")
      .def_readonly("valid", &validation::ValidationResult::valid)
      .def_readonly("error_message",
                    &validation::ValidationResult::error_message)
      .def("__bool__",
           [](const validation::ValidationResult &r) { return r.valid; });

  validation_m.def("validate_url", &validation::validate_url,
                   "Validate URL format", py::arg("url"));

  validation_m.def("validate_ip", &validation::validate_ip,
                   "Validate IP address (IPv4 or IPv6)", py::arg("ip"));

  validation_m.def("validate_domain", &validation::validate_domain,
                   "Validate domain name", py::arg("domain"));

  validation_m.def("validate_email", &validation::validate_email,
                   "Validate email address", py::arg("email"));

  validation_m.def("validate_phone", &validation::validate_phone,
                   "Validate phone number", py::arg("phone"));

  validation_m.def("sanitize_string", &validation::sanitize_string,
                   "Sanitize string (remove control characters)",
                   py::arg("input"));

  // HTTP client module
  py::module http_m = m.def_submodule("http", "HTTP client");

  py::class_<ingest::HttpResponse>(http_m, "HttpResponse")
      .def_readonly("status_code", &ingest::HttpResponse::status_code)
      .def_readonly("body", &ingest::HttpResponse::body)
      .def_readonly("headers", &ingest::HttpResponse::headers)
      .def_readonly("error_message", &ingest::HttpResponse::error_message)
      .def("is_success", &ingest::HttpResponse::is_success);

  py::class_<ingest::HttpConfig>(http_m, "HttpConfig")
      .def(py::init<>())
      .def_readwrite("timeout_seconds", &ingest::HttpConfig::timeout_seconds)
      .def_readwrite("connect_timeout_seconds",
                     &ingest::HttpConfig::connect_timeout_seconds)
      .def_readwrite("verify_ssl", &ingest::HttpConfig::verify_ssl)
      .def_readwrite("user_agent", &ingest::HttpConfig::user_agent)
      .def_readwrite("follow_redirects", &ingest::HttpConfig::follow_redirects)
      .def_readwrite("max_redirects", &ingest::HttpConfig::max_redirects);

  py::class_<ingest::HttpClient>(http_m, "HttpClient")
      .def(py::init<const ingest::HttpConfig &>(),
           py::arg("config") = ingest::HttpConfig())
      .def("get", &ingest::HttpClient::get, "Perform GET request",
           py::arg("url"),
           py::arg("headers") = std::map<std::string, std::string>())
      .def("post", &ingest::HttpClient::post, "Perform POST request",
           py::arg("url"), py::arg("body"),
           py::arg("headers") = std::map<std::string, std::string>())
      .def("set_rate_limit", &ingest::HttpClient::set_rate_limit,
           "Set rate limiting delay in milliseconds", py::arg("delay_ms"));

  // Parser module
  py::module parser_m = m.def_submodule("parsers", "Data parsers");

  parser_m.def(
      "parse_json",
      [](const std::string &input) {
        auto result = ingest::JsonParser::parse(input);
        if (result.is_success()) {
          return py::cast(result.value->dump());
        } else {
          throw std::runtime_error(result.error_message);
        }
      },
      "Parse JSON string", py::arg("input"));

  parser_m.def(
      "parse_html",
      [](const std::string &input) {
        auto result = ingest::XmlParser::parse_html(input);
        if (result.is_success()) {
          return *result.value;
        } else {
          throw std::runtime_error(result.error_message);
        }
      },
      "Parse HTML and extract text", py::arg("input"));

  parser_m.def(
      "extract_links",
      [](const std::string &input) {
        auto result = ingest::XmlParser::extract_links(input);
        if (result.is_success()) {
          return *result.value;
        } else {
          throw std::runtime_error(result.error_message);
        }
      },
      "Extract links from HTML", py::arg("input"));
}
