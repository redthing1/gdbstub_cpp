#pragma once

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <span>
#include <string>
#include <string_view>

#include "gdbstub/protocol/rsp_core.hpp"
#include "gdbstub/server/server.hpp"

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace gdbstub::test {

inline std::span<const std::byte> as_bytes(std::string_view text) {
  return {reinterpret_cast<const std::byte*>(text.data()), text.size()};
}

namespace detail {

#ifdef _WIN32
using socket_type = SOCKET;
constexpr socket_type invalid_socket = INVALID_SOCKET;

inline int close_socket(socket_type sock) { return closesocket(sock); }

struct winsock_guard {
  winsock_guard() {
    WSADATA data;
    WSAStartup(MAKEWORD(2, 2), &data);
  }
  ~winsock_guard() { WSACleanup(); }
};

inline void ensure_winsock() {
  static winsock_guard guard;
  (void) guard;
}
#else
using socket_type = int;
constexpr socket_type invalid_socket = -1;

inline int close_socket(socket_type sock) { return ::close(sock); }

inline void ensure_winsock() {}
#endif

class socket_handle {
public:
  socket_handle() = default;
  explicit socket_handle(socket_type sock) : sock_(sock) {}

  socket_handle(socket_handle&& other) noexcept : sock_(other.release()) {}
  socket_handle& operator=(socket_handle&& other) noexcept {
    if (this != &other) {
      close();
      sock_ = other.release();
    }
    return *this;
  }

  socket_handle(const socket_handle&) = delete;
  socket_handle& operator=(const socket_handle&) = delete;

  ~socket_handle() { close(); }

  socket_type get() const { return sock_; }
  bool valid() const { return sock_ != invalid_socket; }

  socket_type release() {
    socket_type current = sock_;
    sock_ = invalid_socket;
    return current;
  }

  void reset(socket_type sock = invalid_socket) {
    close();
    sock_ = sock;
  }

  void close() {
    if (sock_ != invalid_socket) {
      close_socket(sock_);
      sock_ = invalid_socket;
    }
  }

private:
  socket_type sock_ = invalid_socket;
};

inline void set_client_socket_options(socket_type sock) {
#ifdef SO_NOSIGPIPE
  int yes = 1;
  setsockopt(sock, SOL_SOCKET, SO_NOSIGPIPE, reinterpret_cast<const char*>(&yes), sizeof(yes));
#endif
}

inline std::ptrdiff_t socket_read(socket_type sock, std::span<std::byte> out) {
  if (out.empty()) {
    return 0;
  }
  const auto size = static_cast<int>(std::min(out.size(), static_cast<size_t>(std::numeric_limits<int>::max())));
#ifdef _WIN32
  return recv(sock, reinterpret_cast<char*>(out.data()), size, 0);
#else
  return recv(sock, out.data(), static_cast<size_t>(size), 0);
#endif
}

inline std::ptrdiff_t socket_write(socket_type sock, std::span<const std::byte> data) {
  if (data.empty()) {
    return 0;
  }
  const auto size = static_cast<int>(std::min(data.size(), static_cast<size_t>(std::numeric_limits<int>::max())));
#ifdef _WIN32
  return send(sock, reinterpret_cast<const char*>(data.data()), size, 0);
#else
  int flags = 0;
#ifdef MSG_NOSIGNAL
  flags |= MSG_NOSIGNAL;
#endif
  return send(sock, data.data(), static_cast<size_t>(size), flags);
#endif
}

inline bool socket_readable(socket_type sock, std::chrono::milliseconds timeout) {
#ifdef _WIN32
  fd_set read_set;
  FD_ZERO(&read_set);
  FD_SET(sock, &read_set);
  timeval tv;
  tv.tv_sec = static_cast<long>(timeout.count() / 1000);
  tv.tv_usec = static_cast<long>((timeout.count() % 1000) * 1000);
  int result = select(0, &read_set, nullptr, nullptr, &tv);
  return result > 0 && FD_ISSET(sock, &read_set);
#else
  pollfd pfd{};
  pfd.fd = sock;
  pfd.events = POLLIN;
  int ms = static_cast<int>(std::min<std::chrono::milliseconds::rep>(timeout.count(), std::numeric_limits<int>::max()));
  int result = poll(&pfd, 1, ms);
  return result > 0 && (pfd.revents & POLLIN);
#endif
}

} // namespace detail

struct client_reply {
  std::string payload;
  bool checksum_ok = true;
  size_t ack_count = 0;
  size_t nack_count = 0;
  bool is_notification = false;
};

class tcp_client {
public:
  tcp_client() { detail::ensure_winsock(); }
  ~tcp_client() { close(); }

  tcp_client(const tcp_client&) = delete;
  tcp_client& operator=(const tcp_client&) = delete;

  bool connect(std::string_view host, uint16_t port) {
    close();

    addrinfo hints{};
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC;
    addrinfo* result = nullptr;

    std::string host_str(host);
    std::string port_str = std::to_string(port);

    if (getaddrinfo(host_str.c_str(), port_str.c_str(), &hints, &result) != 0) {
      return false;
    }

    for (addrinfo* rp = result; rp != nullptr; rp = rp->ai_next) {
      detail::socket_type sock = ::socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
      if (sock == detail::invalid_socket) {
        continue;
      }
      if (::connect(sock, rp->ai_addr, static_cast<int>(rp->ai_addrlen)) == 0) {
        sock_.reset(sock);
        detail::set_client_socket_options(sock);
        break;
      }
      detail::close_socket(sock);
    }

    freeaddrinfo(result);
    return sock_.valid();
  }

  bool send_packet(std::string_view payload) {
    auto packet = rsp::build_packet(payload);
    return send_bytes(as_bytes(packet));
  }

  std::optional<client_reply> read_packet(std::chrono::milliseconds timeout) {
    client_reply reply;
    auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
      auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now());
      if (!detail::socket_readable(sock_.get(), remaining)) {
        continue;
      }

      std::array<std::byte, 4096> buffer{};
      auto bytes = detail::socket_read(sock_.get(), buffer);
      if (bytes <= 0) {
        return std::nullopt;
      }

      parser_.append(std::span<const std::byte>(buffer.data(), static_cast<size_t>(bytes)));
      while (parser_.has_event()) {
        auto event = parser_.pop_event();
        if (event.kind == rsp::event_kind::ack) {
          ++reply.ack_count;
          continue;
        }
        if (event.kind == rsp::event_kind::nack) {
          ++reply.nack_count;
          continue;
        }
        if (event.kind == rsp::event_kind::notification) {
          continue;
        }
        if (event.kind == rsp::event_kind::packet) {
          reply.payload = std::move(event.payload);
          reply.checksum_ok = event.checksum_ok;
          send_ack();
          return reply;
        }
      }
    }
    return std::nullopt;
  }

  std::optional<client_reply> read_event(std::chrono::milliseconds timeout) {
    client_reply reply;
    auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
      auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now());
      if (!detail::socket_readable(sock_.get(), remaining)) {
        continue;
      }

      std::array<std::byte, 4096> buffer{};
      auto bytes = detail::socket_read(sock_.get(), buffer);
      if (bytes <= 0) {
        return std::nullopt;
      }

      parser_.append(std::span<const std::byte>(buffer.data(), static_cast<size_t>(bytes)));
      while (parser_.has_event()) {
        auto event = parser_.pop_event();
        if (event.kind == rsp::event_kind::ack) {
          ++reply.ack_count;
          continue;
        }
        if (event.kind == rsp::event_kind::nack) {
          ++reply.nack_count;
          continue;
        }
        if (event.kind == rsp::event_kind::notification) {
          reply.payload = std::move(event.payload);
          reply.checksum_ok = event.checksum_ok;
          reply.is_notification = true;
          return reply;
        }
        if (event.kind == rsp::event_kind::packet) {
          reply.payload = std::move(event.payload);
          reply.checksum_ok = event.checksum_ok;
          send_ack();
          return reply;
        }
      }
    }
    return std::nullopt;
  }

  void close() { sock_.close(); }

private:
  bool send_bytes(std::span<const std::byte> data) {
    size_t offset = 0;
    while (offset < data.size()) {
      auto written = detail::socket_write(sock_.get(), data.subspan(offset));
      if (written <= 0) {
        return false;
      }
      offset += static_cast<size_t>(written);
    }
    return true;
  }

  void send_ack() {
    std::array<std::byte, 1> ack = {std::byte{static_cast<unsigned char>(rsp::ack_char)}};
    (void) send_bytes(ack);
  }

  detail::socket_handle sock_;
  rsp::stream_parser parser_;
};

inline std::optional<uint16_t> listen_on_available_port(
    server& server,
    std::string_view host,
    uint16_t base_port,
    uint16_t max_attempts
) {
  for (uint16_t offset = 0; offset < max_attempts; ++offset) {
    uint16_t port = static_cast<uint16_t>(base_port + offset);
    std::string address = std::string(host) + ":" + std::to_string(port);
    if (server.listen(address)) {
      return port;
    }
  }
  return std::nullopt;
}

inline std::optional<client_reply> wait_for_reply(
    server& server,
    tcp_client& client,
    std::chrono::milliseconds timeout
) {
  auto deadline = std::chrono::steady_clock::now() + timeout;
  while (std::chrono::steady_clock::now() < deadline) {
    server.poll(std::chrono::milliseconds(10));
    if (auto reply = client.read_packet(std::chrono::milliseconds(10))) {
      return reply;
    }
  }
  return std::nullopt;
}

inline std::optional<client_reply> wait_for_event(
    server& server,
    tcp_client& client,
    std::chrono::milliseconds timeout
) {
  auto deadline = std::chrono::steady_clock::now() + timeout;
  while (std::chrono::steady_clock::now() < deadline) {
    server.poll(std::chrono::milliseconds(10));
    if (auto reply = client.read_event(std::chrono::milliseconds(10))) {
      return reply;
    }
  }
  return std::nullopt;
}

} // namespace gdbstub::test
