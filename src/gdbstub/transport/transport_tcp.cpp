#include "gdbstub/transport/transport_tcp.hpp"

#include <algorithm>
#include <limits>
#include <optional>
#include <string>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <poll.h>
#endif

namespace gdbstub {

namespace {

#ifdef _WIN32
using socket_type = SOCKET;
constexpr socket_type invalid_socket = INVALID_SOCKET;

int close_socket(socket_type s) { return closesocket(s); }
struct winsock_guard {
  winsock_guard() {
    WSADATA data;
    WSAStartup(MAKEWORD(2, 2), &data);
  }
  ~winsock_guard() { WSACleanup(); }
};

void ensure_winsock() {
  static winsock_guard guard;
  (void) guard;
}
#else
using socket_type = int;
constexpr socket_type invalid_socket = -1;

int close_socket(socket_type s) { return ::close(s); }
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

struct host_port {
  std::string host;
  std::string port;
};

std::optional<host_port> parse_address(std::string_view address) {
  if (address.empty()) {
    return std::nullopt;
  }

  std::string_view host;
  std::string_view port;

  if (address.front() == '[') {
    auto end = address.find(']');
    if (end == std::string_view::npos) {
      return std::nullopt;
    }
    if (end + 1 >= address.size() || address[end + 1] != ':') {
      return std::nullopt;
    }
    host = address.substr(1, end - 1);
    port = address.substr(end + 2);
  } else {
    auto first_colon = address.find(':');
    auto last_colon = address.rfind(':');
    if (first_colon != std::string_view::npos && first_colon != last_colon) {
      return std::nullopt;
    }
    if (last_colon == std::string_view::npos) {
      host = "";
      port = address;
    } else {
      host = address.substr(0, last_colon);
      port = address.substr(last_colon + 1);
    }
  }

  if (port.empty()) {
    return std::nullopt;
  }

  std::string host_str(host);
  if (host_str == "*") {
    host_str.clear();
  }

  return host_port{host_str, std::string(port)};
}

void set_socket_options(socket_type sock) {
  int yes = 1;
  setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&yes), sizeof(yes));
#ifdef SO_REUSEPORT
  setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, reinterpret_cast<const char*>(&yes), sizeof(yes));
#endif
#ifdef SO_NOSIGPIPE
  setsockopt(sock, SOL_SOCKET, SO_NOSIGPIPE, reinterpret_cast<const char*>(&yes), sizeof(yes));
#endif
}

std::ptrdiff_t socket_read(socket_type sock, std::span<std::byte> out) {
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

std::ptrdiff_t socket_write(socket_type sock, std::span<const std::byte> data) {
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

bool socket_readable(socket_type sock, std::chrono::milliseconds timeout) {
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

} // namespace

class transport_tcp::impl {
public:
  impl() {
#ifdef _WIN32
    ensure_winsock();
#endif
  }

  bool listen(std::string_view address) {
    close();

    auto parsed = parse_address(address);
    if (!parsed) {
      return false;
    }

    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    const char* host = parsed->host.empty() ? nullptr : parsed->host.c_str();
    addrinfo* result = nullptr;
    if (getaddrinfo(host, parsed->port.c_str(), &hints, &result) != 0) {
      return false;
    }

    for (addrinfo* rp = result; rp != nullptr; rp = rp->ai_next) {
      socket_type sock = ::socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
      if (sock == invalid_socket) {
        continue;
      }

      set_socket_options(sock);
      if (::bind(sock, rp->ai_addr, static_cast<int>(rp->ai_addrlen)) != 0) {
        close_socket(sock);
        continue;
      }

      if (::listen(sock, SOMAXCONN) != 0) {
        close_socket(sock);
        continue;
      }

      listen_socket_.reset(sock);
      break;
    }

    freeaddrinfo(result);
    return listen_socket_.valid();
  }

  bool accept() {
    if (!listen_socket_.valid()) {
      return false;
    }

    socket_type sock = ::accept(listen_socket_.get(), nullptr, nullptr);
    if (sock == invalid_socket) {
      return false;
    }

    set_socket_options(sock);
    conn_socket_.reset(sock);
    return true;
  }

  bool connected() const { return conn_socket_.valid(); }

  bool readable(std::chrono::milliseconds timeout) {
    if (!conn_socket_.valid()) {
      return false;
    }
    return socket_readable(conn_socket_.get(), timeout);
  }

  std::ptrdiff_t read(std::span<std::byte> out) {
    if (!conn_socket_.valid()) {
      return -1;
    }
    return socket_read(conn_socket_.get(), out);
  }

  std::ptrdiff_t write(std::span<const std::byte> data) {
    if (!conn_socket_.valid()) {
      return -1;
    }
    return socket_write(conn_socket_.get(), data);
  }

  void disconnect() { conn_socket_.close(); }

  void close() {
    conn_socket_.close();
    listen_socket_.close();
  }

private:
  socket_handle listen_socket_;
  socket_handle conn_socket_;
};

transport_tcp::transport_tcp() : impl_(std::make_unique<impl>()) {}
transport_tcp::~transport_tcp() = default;

transport_tcp::transport_tcp(transport_tcp&&) noexcept = default;
transport_tcp& transport_tcp::operator=(transport_tcp&&) noexcept = default;

bool transport_tcp::listen(std::string_view address) { return impl_->listen(address); }
bool transport_tcp::accept() { return impl_->accept(); }
bool transport_tcp::connected() const { return impl_->connected(); }
bool transport_tcp::readable(std::chrono::milliseconds timeout) { return impl_->readable(timeout); }
std::ptrdiff_t transport_tcp::read(std::span<std::byte> out) { return impl_->read(out); }
std::ptrdiff_t transport_tcp::write(std::span<const std::byte> data) { return impl_->write(data); }
void transport_tcp::disconnect() { impl_->disconnect(); }
void transport_tcp::close() { impl_->close(); }

} // namespace gdbstub
