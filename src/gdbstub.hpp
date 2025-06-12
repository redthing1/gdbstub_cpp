/**
 * gdbstub.hpp - A modern C++17 header-only GDB Remote Serial Protocol implementation
 *
 * This library provides a complete implementation of the GDB Remote Serial Protocol,
 * allowing emulators and embedded systems to be debugged using GDB and LLDB.
 *
 * Features:
 * - Header-only, no dependencies beyond standard C++17
 * - Supports incremental functionality (SFINAE-based feature detection)
 * - Three integration patterns: blocking, polling, and callback-based
 * - Cross-platform (Windows/Linux/macOS)
 * - Memory efficient with reusable buffers
 * - Full protocol compliance
 *
 * Basic usage:
 * ```cpp
 * struct my_emulator {
 *     // Required methods
 *     gdb_action cont() { ... }
 *     gdb_action stepi() { ... }
 *     size_t reg_size(int regno) const { ... }
 *     int read_reg(int regno, void* data) { ... }
 *     int write_reg(int regno, const void* data) { ... }
 *     int read_mem(size_t addr, size_t len, void* data) { ... }
 *     int write_mem(size_t addr, size_t len, const void* data) { ... }
 *
 *     // Optional methods (detected automatically)
 *     bool set_breakpoint(size_t addr, breakpoint_type type) { ... }
 *     bool del_breakpoint(size_t addr, breakpoint_type type) { ... }
 *     gdbstub::host_info get_host_info() { return {"riscv64-unknown-elf", "little", 8}; }
 *     std::optional<gdbstub::mem_region> get_mem_region_info(size_t addr) { ... }
 *     std::optional<gdbstub::register_info> get_register_info(int regno) { ... }
 *     void on_interrupt() { ... }
 * };
 *
 * my_emulator emu;
 * gdbstub::arch_info arch = {
 *   .target_desc = "...",
 *   .xml_architecture_name = "riscv", // For 'xmlRegisters' GDB feature
 *   .reg_count = 33,
 *   .pc_reg_num = 32
 * };
 * gdbstub::serve(emu, arch, "localhost:1234");
 * ```
 *
 * Register numbering note:
 * The target is responsible for mapping register numbers to actual registers.
 * For example, in RISC-V, register 32 might be the PC. The target's read_reg
 * and write_reg methods should handle these special cases.
 */

#pragma once

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <charconv>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <functional>
#include <iostream>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <tuple>
#include <type_traits>
#include <utility>
#include <vector>

// Platform-specific networking includes
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>
#endif

// Optional GDB remote serial protocol debugging
// Uncomment to enable packet-level debugging output
// #define GDBSTUB_DEBUG
#ifdef GDBSTUB_DEBUG
#define GDBSTUB_LOG(fmt, ...)                                                                                          \
  do {                                                                                                                 \
    fprintf(stderr, "[GDBSTUB] " fmt "\n", ##__VA_ARGS__);                                                             \
  } while (0)
#else
#define GDBSTUB_LOG(fmt, ...)                                                                                          \
  do {                                                                                                                 \
  } while (0)
#endif

namespace gdbstub {

// =============================================================================
// Core types and constants
// =============================================================================

/**
 * @brief Actions that target operations can return to control debugger flow.
 */
enum class gdb_action {
  none,    ///< No special action, continue debugging normally
  stop,    ///< Target hit breakpoint or completed step, send stop reply
  shutdown ///< Target wants to terminate debugging session
};

/**
 * @brief Breakpoint types supported by the GDB protocol.
 *
 * Note: To support watchpoints, the Target should handle the corresponding
 * write/read/access watchpoint types in its set/del_breakpoint methods.
 */
enum class breakpoint_type {
  software = 0,         ///< Software breakpoint (e.g., BKPT instruction)
  hardware = 1,         ///< Hardware breakpoint
  write_watchpoint = 2, ///< Break on memory write
  read_watchpoint = 3,  ///< Break on memory read
  access_watchpoint = 4 ///< Break on memory access (read or write)
};

/**
 * @brief GDB signal numbers (subset of Unix signals).
 */
enum class gdb_signal {
  trap = 5 ///< SIGTRAP - typically used for breakpoint or single-step completion
};

/**
 * @brief Architecture description for the target system.
 */
struct arch_info {
  const char* target_desc = nullptr;           ///< XML target description string.
  const char* xml_architecture_name = nullptr; ///< Name for the register set in XML, e.g., "riscv", "i386".
  int cpu_count = 1;                           ///< Number of CPUs/cores for SMP systems.
  int reg_count = 0;                           ///< Number of registers in the target architecture.
  int pc_reg_num = -1;                         ///< Register number of the Program Counter (PC).
};

/**
 * @brief Information about the host system, used for auto-detection by LLDB.
 *
 * The Target should populate this with its specific details.
 */
struct host_info {
  const char* triple = "unknown-unknown-unknown"; ///< Target triple, e.g., "riscv64-unknown-elf".
  const char* endian = "little";                  ///< "little" or "big".
  int ptr_size = 0;                               ///< Pointer size in bytes.
};

/**
 * @brief Describes a region of memory for the qMemoryRegionInfo packet.
 */
struct mem_region {
  size_t start;            ///< Start address of the region.
  size_t size;             ///< Size of the region in bytes.
  const char* permissions; ///< Permissions string, e.g., "r", "rw", "rx".
};

/**
 * @brief Detailed information about a single register, for qRegisterInfo.
 *
 * This information is used by LLDB to display register information correctly.
 * The `offset` field must be the byte offset of this register within the 'g' packet response.
 */
struct register_info {
  const char* name = "unknown";                  ///< e.g., "x0", "pc", "sp"
  const char* alt_name = nullptr;                ///< e.g., "zero" for x0
  const char* set = "General Purpose Registers"; ///< Register set name
  const char* generic = nullptr;                 ///< Generic name like "pc", "sp", "fp", "ra"
  const char* encoding = "uint";                 ///< "uint", "ieee754", "vector"
  const char* format = "hex";                    ///< "hex", "decimal", "float"
  int bitsize = 0;                               ///< Size of the register in bits
  int offset = 0;                                ///< Offset in the 'g' packet
  int dwarf_regnum = -1;                         ///< DWARF register number
};

// =============================================================================
// Implementation details
// =============================================================================

namespace detail {

// GDB protocol error codes (subset of standard errno values)
enum class gdb_errno : int {
  gdb_EPERM = 0x01,  ///< Operation not permitted
  gdb_ENOENT = 0x02, ///< No such file or directory
  gdb_EINTR = 0x04,  ///< Interrupted system call
  gdb_EBADF = 0x09,  ///< Bad file number
  gdb_EACCES = 0x0D, ///< Permission denied
  gdb_EFAULT = 0x0E, ///< Bad address
  gdb_EBUSY = 0x10,  ///< Device or resource busy
  gdb_EINVAL = 0x16, ///< Invalid argument
  gdb_ENOSPC = 0x1c, ///< No space left on device
};

// Protocol constants
constexpr size_t MAX_PACKET_SIZE = 4096;        ///< Maximum packet size we support.
constexpr size_t MAX_MEMORY_READ = 2048;        ///< Maximum memory read size per packet.
constexpr size_t MAX_REG_SIZE = 256;            ///< Maximum register size in bytes.
constexpr size_t PACKET_GARBAGE_THRESHOLD = 16; ///< Buffer size before clearing garbage.
constexpr size_t PACKET_OVERHEAD_SIZE = 16;     ///< Estimated packet overhead for transfers.

// Platform abstraction for sockets
#ifdef _WIN32
using socket_type = SOCKET;
constexpr socket_type invalid_socket = INVALID_SOCKET;

/**
 * RAII wrapper for Windows socket initialization
 */
struct winsock_init {
  winsock_init() {
    WSADATA wsa_data;
    WSAStartup(MAKEWORD(2, 2), &wsa_data);
  }
  ~winsock_init() { WSACleanup(); }
};

inline void close_socket(socket_type s) { closesocket(s); }
inline int get_last_error() { return WSAGetLastError(); }
inline bool would_block(int error) { return error == WSAEWOULDBLOCK; }
#else
using socket_type = int;
constexpr socket_type invalid_socket = -1;

struct winsock_init {}; // No-op on Unix
inline void close_socket(socket_type s) { ::close(s); }
inline int get_last_error() { return errno; }
inline bool would_block(int error) { return error == EAGAIN || error == EWOULDBLOCK; }
#endif

/**
 * @brief RAII socket wrapper with move semantics.
 */
class socket {
  socket_type sock_ = invalid_socket;

public:
  socket() = default;
  explicit socket(socket_type s) noexcept : sock_(s) {}

  socket(socket&& other) noexcept : sock_(std::exchange(other.sock_, invalid_socket)) {}
  socket& operator=(socket&& other) noexcept {
    if (this != &other) {
      close();
      sock_ = std::exchange(other.sock_, invalid_socket);
    }
    return *this;
  }

  socket(const socket&) = delete;
  socket& operator=(const socket&) = delete;

  ~socket() { close(); }

  void close() noexcept {
    if (sock_ != invalid_socket) {
      close_socket(sock_);
      sock_ = invalid_socket;
    }
  }

  socket_type get() const noexcept { return sock_; }
  socket_type release() noexcept { return std::exchange(sock_, invalid_socket); }
  bool valid() const noexcept { return sock_ != invalid_socket; }
  explicit operator bool() const noexcept { return valid(); }
};

// Socket operations
inline ssize_t socket_read(socket_type sock, void* buf, size_t len) {
#ifdef _WIN32
  return recv(sock, static_cast<char*>(buf), static_cast<int>(len), 0);
#else
  return read(sock, buf, len);
#endif
}

inline ssize_t socket_write(socket_type sock, const void* buf, size_t len) {
#ifdef _WIN32
  return send(sock, static_cast<const char*>(buf), static_cast<int>(len), 0);
#else
  return write(sock, buf, len);
#endif
}

inline bool socket_readable(socket_type sock, int timeout_ms) {
#ifdef _WIN32
  fd_set read_set;
  FD_ZERO(&read_set);
  FD_SET(sock, &read_set);

  if (timeout_ms < 0) {
    return select(0, &read_set, nullptr, nullptr, nullptr) > 0;
  } else {
    timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    return select(0, &read_set, nullptr, nullptr, &tv) > 0;
  }
#else
  pollfd pfd{};
  pfd.fd = sock;
  pfd.events = POLLIN;
  return poll(&pfd, 1, timeout_ms) > 0 && (pfd.revents & POLLIN);
#endif
}

// Hex conversion utilities
constexpr char hex_chars[] = "0123456789abcdef";

/**
 * @brief Convert a hex character to its numeric value.
 */
constexpr uint8_t hex_to_nibble(char c) noexcept {
  if (c >= '0' && c <= '9') {
    return c - '0';
  }
  if (c >= 'a' && c <= 'f') {
    return c - 'a' + 10;
  }
  if (c >= 'A' && c <= 'F') {
    return c - 'A' + 10;
  }
  return 0xff; // Invalid hex char
}

/**
 * @brief Convert binary data to hex string.
 */
inline void bytes_to_hex(const void* bytes, size_t len, char* hex) noexcept {
  const auto* p = static_cast<const uint8_t*>(bytes);
  for (size_t i = 0; i < len; ++i) {
    hex[i * 2] = hex_chars[p[i] >> 4];
    hex[i * 2 + 1] = hex_chars[p[i] & 0xf];
  }
  hex[len * 2] = '\0';
}

/**
 * @brief Convert hex string to binary data.
 */
inline bool hex_to_bytes(const char* hex, size_t hex_len, void* bytes) noexcept {
  if (hex_len % 2 != 0) {
    return false;
  }

  auto* p = static_cast<uint8_t*>(bytes);
  for (size_t i = 0; i < hex_len; i += 2) {
    uint8_t high = hex_to_nibble(hex[i]);
    uint8_t low = hex_to_nibble(hex[i + 1]);
    if (high == 0xff || low == 0xff) {
      return false;
    }
    p[i / 2] = (high << 4) | low;
  }
  return true;
}

/**
 * @brief Compute GDB packet checksum.
 */
inline uint8_t compute_checksum(std::string_view data) noexcept {
  uint8_t sum = 0;
  for (char c : data) {
    sum += static_cast<uint8_t>(c);
  }
  return sum;
}

/**
 * @brief Unescape binary data in 'X' packets ('}' followed by char XOR 0x20).
 */
inline size_t unescape_binary(char* data, size_t len) noexcept {
  char* write_ptr = data;
  const char* read_ptr = data;
  const char* end = data + len;

  while (read_ptr < end) {
    if (*read_ptr == '}' && read_ptr + 1 < end) {
      *write_ptr++ = *(read_ptr + 1) ^ 0x20;
      read_ptr += 2;
    } else {
      *write_ptr++ = *read_ptr++;
    }
  }

  return write_ptr - data;
}

// SFINAE helpers for detecting optional target methods
template <typename T, typename = void> struct has_breakpoints : std::false_type {};
template <typename T>
struct has_breakpoints<
    T, std::void_t<
           decltype(std::declval<T&>().set_breakpoint(size_t{}, breakpoint_type{})),
           decltype(std::declval<T&>().del_breakpoint(size_t{}, breakpoint_type{}))>> : std::true_type {};

template <typename T, typename = void> struct has_cpu_ops : std::false_type {};
template <typename T>
struct has_cpu_ops<
    T, std::void_t<decltype(std::declval<T&>().set_cpu(int{})), decltype(std::declval<const T&>().get_cpu())>>
    : std::true_type {};

template <typename T, typename = void> struct has_interrupt : std::false_type {};
template <typename T>
struct has_interrupt<T, std::void_t<decltype(std::declval<T&>().on_interrupt())>> : std::true_type {};

template <typename T, typename = void> struct has_host_info : std::false_type {};
template <typename T>
struct has_host_info<T, std::void_t<decltype(std::declval<T&>().get_host_info())>> : std::true_type {};

template <typename T, typename = void> struct has_mem_region_info : std::false_type {};
template <typename T>
struct has_mem_region_info<T, std::void_t<decltype(std::declval<T&>().get_mem_region_info(size_t{}))>>
    : std::true_type {};

template <typename T, typename = void> struct has_register_info : std::false_type {};
template <typename T>
struct has_register_info<T, std::void_t<decltype(std::declval<T&>().get_register_info(int{}))>> : std::true_type {};

// Convenience aliases
template <typename T> inline constexpr bool has_breakpoints_v = has_breakpoints<T>::value;
template <typename T> inline constexpr bool has_cpu_ops_v = has_cpu_ops<T>::value;
template <typename T> inline constexpr bool has_interrupt_v = has_interrupt<T>::value;
template <typename T> inline constexpr bool has_host_info_v = has_host_info<T>::value;
template <typename T> inline constexpr bool has_mem_region_info_v = has_mem_region_info<T>::value;
template <typename T> inline constexpr bool has_register_info_v = has_register_info<T>::value;

} // namespace detail

// =============================================================================
// Packet buffer for efficient packet handling
// =============================================================================

/**
 * @brief Buffer for building and parsing GDB packets.
 *
 * This class handles the GDB packet format: $<data>#<checksum>.
 * It automatically finds packet boundaries and validates checksums.
 */
class packet_buffer {
  static constexpr size_t initial_capacity = 1024;

  std::vector<char> buffer_;
  size_t size_ = 0;
  std::optional<size_t> packet_end_;
  bool ack_sent_ = false;

public:
  packet_buffer() : buffer_(initial_capacity) {}

  /**
   * @brief Append data received from the transport layer.
   */
  void append(const char* data, size_t len) {
    if (size_ + len > buffer_.size()) {
      buffer_.resize((size_ + len) * 2);
    }
    std::memcpy(buffer_.data() + size_, data, len);
    size_ += len;
  }

  /**
   * @brief Check if the buffer contains a complete packet.
   * A complete packet has the format: $<data>#<2-digit-checksum>
   */
  bool has_complete_packet() {
    if (packet_end_) {
      return true;
    }

    // Find packet start ($)
    auto start = std::find(buffer_.data(), buffer_.data() + size_, '$');
    if (start == buffer_.data() + size_) {
      // No packet start found - keep a reasonable tail in case '$' arrives later
      if (size_ > detail::PACKET_GARBAGE_THRESHOLD) {
        size_ = 0; // Clear if we have too much garbage
      }
      return false;
    }

    // Shift buffer to start at packet
    if (start != buffer_.data()) {
      size_t offset = start - buffer_.data();
      std::memmove(buffer_.data(), start, size_ - offset);
      size_ -= offset;
    }

    // Find packet end (#)
    auto end = std::find(buffer_.data(), buffer_.data() + size_, '#');
    if (end == buffer_.data() + size_) {
      return false; // Incomplete packet
    }

    // Check if we have checksum (2 chars after #)
    size_t payload_end = end - buffer_.data();
    if (size_ < payload_end + 3) { // # + 2 checksum chars
      return false;
    }

    packet_end_ = payload_end + 3;
    return true;
  }

  /**
   * @brief Check if an ACK needs to be sent for the current packet.
   */
  bool needs_ack() const { return packet_end_.has_value() && !ack_sent_; }

  /**
   * @brief Mark that an ACK has been sent for the current packet.
   */
  void mark_ack_sent() { ack_sent_ = true; }

  /**
   * @brief Get the complete packet including frame ($...#XX).
   */
  std::string_view get_packet() const {
    if (!packet_end_) {
      return {};
    }
    return {buffer_.data(), *packet_end_};
  }

  /**
   * @brief Get the packet payload (data between $ and #).
   */
  std::string_view get_payload() const {
    if (!packet_end_ || *packet_end_ < 4) {
      return {};
    }
    return {buffer_.data() + 1, *packet_end_ - 4};
  }

  /**
   * @brief Verify the checksum of the current packet.
   */
  bool verify_checksum() const {
    if (!packet_end_) {
      return false;
    }

    auto payload = get_payload();
    auto packet = get_packet();

    uint8_t expected;
    if (!detail::hex_to_bytes(packet.data() + packet.size() - 2, 2, &expected)) {
      return false;
    }

    return detail::compute_checksum(payload) == expected;
  }

  /**
   * @brief Remove the current processed packet from the buffer.
   */
  void consume_packet() {
    if (!packet_end_) {
      return;
    }

    size_t remaining = size_ - *packet_end_;
    if (remaining > 0) {
      std::memmove(buffer_.data(), buffer_.data() + *packet_end_, remaining);
    }
    size_ = remaining;
    packet_end_.reset();
    ack_sent_ = false;
  }

  /**
   * @brief Clear the buffer for reuse.
   */
  void clear() {
    size_ = 0;
    packet_end_.reset();
    ack_sent_ = false;
  }

  /**
   * @brief Build a GDB packet with a calculated checksum.
   */
  std::string_view build_packet(std::string_view data) {
    clear();

    // Ensure capacity
    size_t needed = data.size() + 4; // $data#XX
    if (buffer_.size() < needed) {
      buffer_.resize(needed);
    }

    // Build packet: $<data>#<checksum>
    buffer_[0] = '$';
    std::memcpy(buffer_.data() + 1, data.data(), data.size());
    buffer_[data.size() + 1] = '#';

    // Add 2-digit hex checksum
    uint8_t checksum = detail::compute_checksum(data);
    buffer_[data.size() + 2] = detail::hex_chars[checksum >> 4];
    buffer_[data.size() + 3] = detail::hex_chars[checksum & 0xf];

    size_ = data.size() + 4;
    return {buffer_.data(), size_};
  }
};

// =============================================================================
// Transport layer abstraction
// =============================================================================

/**
 * @brief TCP transport for network debugging.
 */
class tcp_transport {
  detail::socket listen_sock_;
  detail::socket conn_sock_;
  detail::winsock_init wsa_init_;

public:
  tcp_transport() = default;

  /**
   * @brief Listen on a TCP address.
   * @param address Format: "host:port", e.g., "localhost:1234" or "*:1234".
   */
  bool listen(const char* address) {
    GDBSTUB_LOG("[TCP] Starting server on %s", address);
    std::string addr_str(address);

    auto colon_pos = addr_str.rfind(':');
    if (colon_pos == std::string::npos) {
      GDBSTUB_LOG("[ERROR] Invalid TCP address format: %s", address);
      return false;
    }

    std::string host = addr_str.substr(0, colon_pos);
    std::string port_str = addr_str.substr(colon_pos + 1);

    char* end;
    long port = std::strtol(port_str.c_str(), &end, 10);
    if (*end != '\0' || port < 0 || port > 65535) {
      GDBSTUB_LOG("[ERROR] Invalid TCP port: %s", port_str.c_str());
      return false;
    }

    if (host == "localhost") {
      host = "127.0.0.1";
    } else if (host == "*" || host.empty()) {
      host = "0.0.0.0";
    }

    listen_sock_ = detail::socket(::socket(AF_INET, SOCK_STREAM, 0));
    if (!listen_sock_) {
      GDBSTUB_LOG("[ERROR] Failed to create socket: %d", detail::get_last_error());
      return false;
    }

    int opt = 1;
#ifdef _WIN32
    setsockopt(listen_sock_.get(), SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&opt), sizeof(opt));
#else
    setsockopt(listen_sock_.get(), SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#endif

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<uint16_t>(port));

    if (inet_pton(AF_INET, host.c_str(), &addr.sin_addr) != 1) {
      GDBSTUB_LOG("[ERROR] Invalid network address: %s", host.c_str());
      return false;
    }

    if (::bind(listen_sock_.get(), reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
      GDBSTUB_LOG("[ERROR] Failed to bind socket: %d", detail::get_last_error());
      return false;
    }

    if (::listen(listen_sock_.get(), 1) < 0) {
      GDBSTUB_LOG("[ERROR] Failed to listen on socket: %d", detail::get_last_error());
      return false;
    }

    return true;
  }

  /**
   * @brief Accept an incoming connection.
   */
  bool accept() {
    GDBSTUB_LOG("[TCP] Waiting for debugger connection...");
    auto sock = ::accept(listen_sock_.get(), nullptr, nullptr);
    if (sock == detail::invalid_socket) {
      GDBSTUB_LOG("[ERROR] Failed to accept connection: %d", detail::get_last_error());
      return false;
    }
    conn_sock_ = detail::socket(sock);
    GDBSTUB_LOG("[TCP] Debugger connected.");
    return true;
  }

  bool connected() const { return conn_sock_.valid(); }

  ssize_t read(void* buf, size_t len) { return detail::socket_read(conn_sock_.get(), buf, len); }

  ssize_t write(const void* buf, size_t len) {
    size_t total = 0;
    while (total < len) {
      ssize_t n = detail::socket_write(conn_sock_.get(), static_cast<const char*>(buf) + total, len - total);
      if (n <= 0) {
        break;
      }
      total += n;
    }
    return total;
  }

  bool readable(int timeout_ms = 0) { return detail::socket_readable(conn_sock_.get(), timeout_ms); }

  void disconnect() { conn_sock_.close(); }

  void close() {
    conn_sock_.close();
    listen_sock_.close();
  }
};

// Unix domain socket transport (not available on Windows)
#ifndef _WIN32
/**
 * @brief Unix domain socket transport for local debugging.
 */
class unix_transport {
  detail::socket listen_sock_;
  detail::socket conn_sock_;
  std::string path_;

public:
  unix_transport() = default;
  ~unix_transport() {
    if (!path_.empty()) {
      ::unlink(path_.c_str());
    }
  }

  /**
   * @brief Listen on a Unix domain socket path.
   */
  bool listen(const char* path) {
    GDBSTUB_LOG("[UNIX] Starting server on %s", path);
    path_ = path;
    ::unlink(path); // Remove existing socket

    listen_sock_ = detail::socket(::socket(AF_UNIX, SOCK_STREAM, 0));
    if (!listen_sock_) {
      GDBSTUB_LOG("[ERROR] Failed to create socket: %d", detail::get_last_error());
      return false;
    }

    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    std::strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

    if (::bind(listen_sock_.get(), reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
      GDBSTUB_LOG("[ERROR] Failed to bind socket: %d", detail::get_last_error());
      return false;
    }

    if (::listen(listen_sock_.get(), 1) < 0) {
      GDBSTUB_LOG("[ERROR] Failed to listen on socket: %d", detail::get_last_error());
      return false;
    }

    return true;
  }

  bool accept() {
    GDBSTUB_LOG("[UNIX] Waiting for debugger connection...");
    auto sock = ::accept(listen_sock_.get(), nullptr, nullptr);
    if (sock == detail::invalid_socket) {
      GDBSTUB_LOG("[ERROR] Failed to accept connection: %d", detail::get_last_error());
      return false;
    }
    conn_sock_ = detail::socket(sock);
    GDBSTUB_LOG("[UNIX] Debugger connected.");
    return true;
  }

  bool connected() const { return conn_sock_.valid(); }

  ssize_t read(void* buf, size_t len) { return detail::socket_read(conn_sock_.get(), buf, len); }

  ssize_t write(const void* buf, size_t len) {
    size_t total = 0;
    while (total < len) {
      ssize_t n = detail::socket_write(conn_sock_.get(), static_cast<const char*>(buf) + total, len - total);
      if (n <= 0) {
        break;
      }
      total += n;
    }
    return total;
  }

  bool readable(int timeout_ms = 0) { return detail::socket_readable(conn_sock_.get(), timeout_ms); }

  void disconnect() { conn_sock_.close(); }

  void close() {
    conn_sock_.close();
    listen_sock_.close();
    if (!path_.empty()) {
      ::unlink(path_.c_str());
      path_.clear();
    }
  }
};
#endif

// =============================================================================
// Main GDB stub server implementation
// =============================================================================

/**
 * @brief GDB Remote Serial Protocol server.
 *
 * @tparam Target The target system to debug (must implement required interface).
 * @tparam Transport The transport layer (e.g., tcp_transport or unix_transport).
 *
 * Thread safety:
 * - serve_forever() is blocking and not thread-safe with other methods.
 * - poll() should be called from a single thread.
 * - Callbacks (on_break, on_continue, on_detach) are called from the same thread as poll/serve_forever.
 */
template <typename Target, typename Transport = tcp_transport> class server {
  // Verify that the Target class implements the required interface.
  static_assert(
      std::is_invocable_r_v<gdb_action, decltype(&Target::cont), Target*>, "Target must implement: gdb_action cont()"
  );
  static_assert(
      std::is_invocable_r_v<gdb_action, decltype(&Target::stepi), Target*>, "Target must implement: gdb_action stepi()"
  );
  static_assert(
      std::is_invocable_r_v<size_t, decltype(&Target::reg_size), const Target*, int>,
      "Target must implement: size_t reg_size(int regno) const"
  );
  static_assert(
      std::is_invocable_r_v<int, decltype(&Target::read_reg), Target*, int, void*>,
      "Target must implement: int read_reg(int regno, void* data)"
  );
  static_assert(
      std::is_invocable_r_v<int, decltype(&Target::write_reg), Target*, int, const void*>,
      "Target must implement: int write_reg(int regno, const void* data)"
  );
  static_assert(
      std::is_invocable_r_v<int, decltype(&Target::read_mem), Target*, size_t, size_t, void*>,
      "Target must implement: int read_mem(size_t addr, size_t len, void* data)"
  );
  static_assert(
      std::is_invocable_r_v<int, decltype(&Target::write_mem), Target*, size_t, size_t, const void*>,
      "Target must implement: int write_mem(size_t addr, size_t len, const void* data)"
  );

private:
  Target& target_;
  arch_info arch_;
  Transport transport_;

  // Packet handling
  packet_buffer rx_buffer_;
  packet_buffer tx_buffer_;

  // Reusable buffers for efficiency
  mutable std::vector<uint8_t> reg_buffer_;
  mutable std::vector<char> hex_buffer_;

  // Interrupt handling
  std::atomic<bool> async_io_enabled_{false};

  // Protocol state
  bool no_ack_mode_{false};

  // Protocol constants
  static constexpr char ack[] = "+";
  static constexpr char nack[] = "-";
  static constexpr char interrupt_char = '\x03';

public:
  // Integration pattern 3: Callbacks
  std::function<void()> on_break;    ///< Called when target breaks.
  std::function<void()> on_continue; ///< Called when target continues.
  std::function<void()> on_detach;   ///< Called when debugger detaches.

  /**
   * @brief Construct server with a target and its architecture info.
   */
  server(Target& target, const arch_info& arch) : target_(target), arch_(arch) {
    if (arch_.reg_count <= 0) {
      throw std::invalid_argument("invalid register count");
    }
    // Default cpu_count to 1 if not specified.
    if (arch_.cpu_count <= 0) {
      arch_.cpu_count = 1;
    }
  }

  ~server() { stop(); }

  /**
   * @brief Start listening on the specified address.
   * @param address Format: "host:port" for TCP, or a path for a Unix socket.
   */
  bool listen(const char* address) { return transport_.listen(address); }

  /**
   * @brief Wait for a debugger connection (blocking).
   */
  bool wait_for_connection() { return transport_.accept(); }

  /**
   * @brief Check if a debugger is currently connected.
   */
  bool has_connection() const { return transport_.connected(); }

  /**
   * @brief Integration pattern 1: Simple blocking mode.
   * Listens, waits for a connection, and serves requests until the debugger detaches.
   */
  void serve_forever() {
    GDBSTUB_LOG("[SERVER] Starting blocking server loop.");
    if (!wait_for_connection()) {
      GDBSTUB_LOG("[ERROR] Failed to establish initial connection.");
      return;
    }

    while (has_connection()) {
      if (!receive_packet()) {
        break;
      }

      auto action = process_current_packet();
      if (action == gdb_action::shutdown) {
        break;
      }
    }

    GDBSTUB_LOG("[SERVER] serve_forever loop terminated.");
    stop();
  }

  /**
   * @brief Integration pattern 2: Non-blocking poll mode.
   * Process one command if available, suitable for integration into an existing event loop.
   * @param timeout_ms Timeout in milliseconds for waiting for data (0 = non-blocking).
   * @return true if a command was processed.
   */
  bool poll(int timeout_ms = 0) {
    if (!has_connection()) {
      return false;
    }

    // This single call handles reading data and checking for interrupts.
    read_and_process_data(timeout_ms);

    if (rx_buffer_.has_complete_packet()) {
      auto action = process_current_packet();

      if (action == gdb_action::shutdown) {
        transport_.disconnect();
        if (on_detach) {
          on_detach();
        }
      }

      return true;
    }

    return false;
  }

  /**
   * @brief Stop the server and clean up all resources.
   */
  void stop() {
    GDBSTUB_LOG("[SERVER] Stopping transport.");
    transport_.close();
  }

private:
  /**
   * @brief Centralized data reader. Reads from the transport, scans for interrupts
   * if async IO is enabled, and appends valid packet data to the rx_buffer.
   * This is the ONLY function that should call transport_.read().
   * @return Number of bytes read, or <= 0 on error/disconnect.
   */
  ssize_t read_and_process_data(int timeout_ms) {
    if (!transport_.readable(timeout_ms)) {
      return 0; // Timed out, no data
    }

    char temp[1024];
    ssize_t n = transport_.read(temp, sizeof(temp));

    if (n <= 0) {
      GDBSTUB_LOG("[SERVER] Connection closed by peer.");
      transport_.disconnect();
      return n;
    }

    // Scan for interrupt if we are in a 'continue' state.
    if (async_io_enabled_.load(std::memory_order_relaxed)) {
      char* data_start = temp;
      char* data_end = temp + n;

      // Handle multiple interrupts and packet data mixed together
      while (true) {
        auto* interrupt_pos = std::find(data_start, data_end, interrupt_char);

        // Append data before the interrupt (or all data if no interrupt)
        if (interrupt_pos > data_start) {
          rx_buffer_.append(data_start, interrupt_pos - data_start);
        }

        if (interrupt_pos == data_end) {
          break; // No more interrupts in the buffer
        }

        // Handle the interrupt
        handle_interrupt();
        // Move past the processed interrupt character
        data_start = interrupt_pos + 1;
      }
    } else {
      // Not in continue mode, so no interrupts are expected. Append all data.
      rx_buffer_.append(temp, n);
    }

    return n;
  }

  /**
   * @brief Handle an interrupt signal (^C) from the debugger.
   */
  void handle_interrupt() {
    GDBSTUB_LOG("[SERVER] Interrupt (Ctrl+C) received from debugger.");
    if constexpr (detail::has_interrupt_v<Target>) {
      target_.on_interrupt();
    }
  }

  /**
   * @brief Receive a complete packet from the transport (blocking).
   * Sends an ACK/NAK immediately after a complete packet is received (per protocol).
   */
  bool receive_packet() {
    while (!rx_buffer_.has_complete_packet()) {
      if (!transport_.connected()) {
        return false; // Connection lost
      }

      // This is a blocking read that also handles interrupts.
      if (read_and_process_data(-1) <= 0) {
        // Disconnected or error
        GDBSTUB_LOG("[SERVER] Connection lost while waiting for packet.");
        return false;
      }
    }

    // Per protocol, ACK/NAK is the first response.
    // We send ACK here and verify checksum in process_current_packet.
    // While a stricter implementation might NAK on bad checksum,
    // modern GDB is lenient and retransmits on timeout.
    if (rx_buffer_.needs_ack()) {
      send_ack();
      rx_buffer_.mark_ack_sent();
    }

    return true;
  }

  /**
   * @brief Send an acknowledgment ('+').
   */
  void send_ack() { transport_.write(ack, 1); }

  /**
   * @brief Send a packet with a calculated checksum.
   */
  void send_packet(std::string_view data) {
    auto packet = tx_buffer_.build_packet(data);
    GDBSTUB_LOG("TX> %.*s", static_cast<int>(packet.size()), packet.data());
    transport_.write(packet.data(), packet.size());
  }

  /**
   * @brief Send an error response (e.g., "E22").
   */
  void send_error(detail::gdb_errno error_code) {
    char buf[8];
    std::snprintf(buf, sizeof(buf), "E%02x", static_cast<int>(error_code));
    GDBSTUB_LOG("[ERROR] Sending error response: %s", buf);
    send_packet(buf);
  }

  /**
   * @brief Process the current packet in the receive buffer.
   */
  gdb_action process_current_packet() {
    GDBSTUB_LOG("RX< %.*s", static_cast<int>(rx_buffer_.get_packet().size()), rx_buffer_.get_packet().data());

    // Verify checksum before processing.
    if (!rx_buffer_.verify_checksum()) {
      GDBSTUB_LOG(
          "[ERROR] Checksum failed for packet: %.*s", static_cast<int>(rx_buffer_.get_packet().size()),
          rx_buffer_.get_packet().data()
      );
      // A NAK would be sent here, but modern GDB often relies on timeouts.
      // The simple ACK-first model is maintained for compatibility.
      rx_buffer_.consume_packet();
      return gdb_action::none;
    }

    gdb_action action = gdb_action::none;

    auto payload = rx_buffer_.get_payload();
    if (!payload.empty()) {
      action = dispatch_command(payload);
    } else {
      // Empty packet is a no-op, often used for keep-alive
      send_packet("");
    }

    rx_buffer_.consume_packet();
    return action;
  }

  /**
   * @brief Ensure a buffer has the required capacity, resizing if necessary.
   */
  void ensure_buffer_size(std::vector<uint8_t>& buffer, size_t size) const {
    if (buffer.size() < size) {
      buffer.resize(size * 2);
    }
  }

  void ensure_buffer_size(std::vector<char>& buffer, size_t size) const {
    if (buffer.size() < size) {
      buffer.resize(size * 2);
    }
  }

  /**
   * @brief Dispatch a command based on the first character of the packet payload.
   */
  gdb_action dispatch_command(std::string_view payload) {
    char cmd = payload[0];
    auto args = payload.substr(1);

    switch (cmd) {
    // Register operations
    case 'g':
      return handle_read_all_registers();
    case 'G':
      return handle_write_all_registers(args);
    case 'p':
      return handle_read_register(args);
    case 'P':
      return handle_write_register(args);

    // Memory operations
    case 'm':
      return handle_read_memory(args);
    case 'M':
      return handle_write_memory(args);
    case 'X':
      return handle_write_binary_memory(args);

    // Execution control
    case 'c':
      return handle_continue(args);
    case 'C':
      return handle_continue(args); // Continue with signal (signal ignored)
    case 's':
      return handle_step(args);
    case 'S':
      return handle_step(args); // Step with signal (signal ignored)

    // Breakpoints
    case 'z':
      return handle_remove_breakpoint(args);
    case 'Z':
      return handle_insert_breakpoint(args);

    // Queries
    case 'q':
      return handle_query(args);
    case 'Q':
      return handle_set_query(args);
    case 'v':
      return handle_v_packet(args);

    // Thread/CPU control
    case 'H':
      return handle_set_thread(args);
    case 'T':
      return handle_thread_alive(args);

    // Misc
    case '?':
      return handle_halt_reason();
    case 'D':
      return handle_detach();
    case '!':
      return handle_extended_mode();

    default:
      GDBSTUB_LOG("[CMD %c] Unsupported command", cmd);
      send_packet(""); // Unsupported command
      return gdb_action::none;
    }
  }

  // --- Command Handlers ---

  gdb_action handle_read_all_registers() {
    GDBSTUB_LOG("[CMD g] Reading all registers (%d regs)", arch_.reg_count);
    size_t total_hex_size = 0;
    for (int i = 0; i < arch_.reg_count; ++i) {
      size_t reg_size = target_.reg_size(i);
      if (reg_size == 0 || reg_size > detail::MAX_REG_SIZE) {
        send_error(detail::gdb_errno::gdb_EINVAL);
        return gdb_action::none;
      }
      total_hex_size += reg_size * 2;
    }

    if (total_hex_size > detail::MAX_PACKET_SIZE) {
      send_error(detail::gdb_errno::gdb_ENOSPC); // Too large for packet
      return gdb_action::none;
    }

    ensure_buffer_size(hex_buffer_, total_hex_size + 1);
    char* hex_ptr = hex_buffer_.data();

    for (int i = 0; i < arch_.reg_count; ++i) {
      size_t reg_size = target_.reg_size(i);
      ensure_buffer_size(reg_buffer_, reg_size);

      if (target_.read_reg(i, reg_buffer_.data()) != 0) {
        // Per GDB docs, 'xx' indicates an unavailable register.
        std::memset(hex_ptr, 'x', reg_size * 2);
      } else {
        detail::bytes_to_hex(reg_buffer_.data(), reg_size, hex_ptr);
      }
      hex_ptr += reg_size * 2;
    }

    send_packet(std::string_view(hex_buffer_.data(), total_hex_size));
    return gdb_action::none;
  }

  gdb_action handle_write_all_registers(std::string_view args) {
    GDBSTUB_LOG("[CMD G] Writing all registers (%d regs)", arch_.reg_count);
    size_t pos = 0;
    for (int i = 0; i < arch_.reg_count; ++i) {
      size_t reg_size = target_.reg_size(i);
      if (pos + reg_size * 2 > args.size()) {
        send_error(detail::gdb_errno::gdb_EINVAL);
        return gdb_action::none;
      }

      ensure_buffer_size(reg_buffer_, reg_size);
      if (!detail::hex_to_bytes(args.data() + pos, reg_size * 2, reg_buffer_.data())) {
        send_error(detail::gdb_errno::gdb_EINVAL);
        return gdb_action::none;
      }

      if (target_.write_reg(i, reg_buffer_.data()) != 0) {
        GDBSTUB_LOG("[ERROR] Target write_reg failed for reg %d", i);
        send_error(detail::gdb_errno::gdb_EFAULT);
        return gdb_action::none;
      }
      pos += reg_size * 2;
    }

    send_packet("OK");
    return gdb_action::none;
  }

  gdb_action handle_read_register(std::string_view args) {
    int regno;
    auto result = std::from_chars(args.data(), args.data() + args.size(), regno, 16);
    if (result.ec != std::errc{} || regno < 0 || regno >= arch_.reg_count) {
      send_error(detail::gdb_errno::gdb_EINVAL);
      return gdb_action::none;
    }

    GDBSTUB_LOG("[CMD p] Reading register %d", regno);
    size_t reg_size = target_.reg_size(regno);
    if (reg_size == 0 || reg_size > detail::MAX_REG_SIZE) {
      send_error(detail::gdb_errno::gdb_EINVAL);
      return gdb_action::none;
    }

    ensure_buffer_size(reg_buffer_, reg_size);
    if (target_.read_reg(regno, reg_buffer_.data()) != 0) {
      send_error(detail::gdb_errno::gdb_EFAULT);
      return gdb_action::none;
    }

    ensure_buffer_size(hex_buffer_, reg_size * 2 + 1);
    detail::bytes_to_hex(reg_buffer_.data(), reg_size, hex_buffer_.data());

    send_packet(std::string_view(hex_buffer_.data(), reg_size * 2));
    return gdb_action::none;
  }

  gdb_action handle_write_register(std::string_view args) {
    auto eq_pos = args.find('=');
    if (eq_pos == std::string_view::npos) {
      send_error(detail::gdb_errno::gdb_EINVAL);
      return gdb_action::none;
    }

    int regno;
    auto result = std::from_chars(args.data(), args.data() + eq_pos, regno, 16);
    if (result.ec != std::errc{} || regno < 0 || regno >= arch_.reg_count) {
      send_error(detail::gdb_errno::gdb_EINVAL);
      return gdb_action::none;
    }

    auto hex_data = args.substr(eq_pos + 1);
    size_t reg_size = target_.reg_size(regno);
    if (reg_size == 0 || hex_data.size() != reg_size * 2) {
      send_error(detail::gdb_errno::gdb_EINVAL);
      return gdb_action::none;
    }

    GDBSTUB_LOG("[CMD P] Writing register %d (size %zu)", regno, reg_size);
    ensure_buffer_size(reg_buffer_, reg_size);
    if (!detail::hex_to_bytes(hex_data.data(), hex_data.size(), reg_buffer_.data())) {
      send_error(detail::gdb_errno::gdb_EINVAL);
      return gdb_action::none;
    }

    if (target_.write_reg(regno, reg_buffer_.data()) != 0) {
      GDBSTUB_LOG("[ERROR] Target write_reg failed for reg %d", regno);
      send_error(detail::gdb_errno::gdb_EFAULT);
      return gdb_action::none;
    }

    send_packet("OK");
    return gdb_action::none;
  }

  gdb_action handle_read_memory(std::string_view args) {
    auto comma_pos = args.find(',');
    if (comma_pos == std::string_view::npos) {
      send_error(detail::gdb_errno::gdb_EINVAL);
      return gdb_action::none;
    }

    size_t addr, len;
    auto addr_result = std::from_chars(args.data(), args.data() + comma_pos, addr, 16);
    auto len_result = std::from_chars(args.data() + comma_pos + 1, args.data() + args.size(), len, 16);

    if (addr_result.ec != std::errc{} || len_result.ec != std::errc{}) {
      send_error(detail::gdb_errno::gdb_EINVAL);
      return gdb_action::none;
    }

    len = std::min(len, detail::MAX_MEMORY_READ);
    GDBSTUB_LOG("[CMD m] Reading memory at 0x%zx, length %zu", addr, len);
    std::vector<uint8_t> data(len);

    if (target_.read_mem(addr, len, data.data()) != 0) {
      send_error(detail::gdb_errno::gdb_EFAULT);
      return gdb_action::none;
    }

    ensure_buffer_size(hex_buffer_, len * 2 + 1);
    detail::bytes_to_hex(data.data(), len, hex_buffer_.data());

    send_packet(std::string_view(hex_buffer_.data(), len * 2));
    return gdb_action::none;
  }

  gdb_action handle_write_memory(std::string_view args) {
    auto colon_pos = args.find(':');
    if (colon_pos == std::string_view::npos) {
      send_error(detail::gdb_errno::gdb_EINVAL);
      return gdb_action::none;
    }

    auto comma_pos = args.find(',', 0);
    if (comma_pos == std::string_view::npos || comma_pos > colon_pos) {
      send_error(detail::gdb_errno::gdb_EINVAL);
      return gdb_action::none;
    }

    size_t addr, len;
    auto addr_result = std::from_chars(args.data(), args.data() + comma_pos, addr, 16);
    auto len_result = std::from_chars(args.data() + comma_pos + 1, args.data() + colon_pos, len, 16);

    if (addr_result.ec != std::errc{} || len_result.ec != std::errc{}) {
      send_error(detail::gdb_errno::gdb_EINVAL);
      return gdb_action::none;
    }

    GDBSTUB_LOG("[CMD M] Writing memory at 0x%zx, length %zu", addr, len);
    auto hex_data = args.substr(colon_pos + 1);
    if (hex_data.size() != len * 2) {
      send_error(detail::gdb_errno::gdb_EINVAL);
      return gdb_action::none;
    }

    std::vector<uint8_t> data(len);
    if (!detail::hex_to_bytes(hex_data.data(), hex_data.size(), data.data())) {
      send_error(detail::gdb_errno::gdb_EINVAL);
      return gdb_action::none;
    }

    if (target_.write_mem(addr, len, data.data()) != 0) {
      send_error(detail::gdb_errno::gdb_EFAULT);
      return gdb_action::none;
    }

    send_packet("OK");
    return gdb_action::none;
  }

  gdb_action handle_write_binary_memory(std::string_view args) {
    auto colon_pos = args.find(':');
    if (colon_pos == std::string_view::npos) {
      send_error(detail::gdb_errno::gdb_EINVAL);
      return gdb_action::none;
    }

    auto comma_pos = args.find(',');
    if (comma_pos == std::string_view::npos || comma_pos > colon_pos) {
      send_error(detail::gdb_errno::gdb_EINVAL);
      return gdb_action::none;
    }

    size_t addr, len;
    auto addr_result = std::from_chars(args.data(), args.data() + comma_pos, addr, 16);
    auto len_result = std::from_chars(args.data() + comma_pos + 1, args.data() + colon_pos, len, 16);

    if (addr_result.ec != std::errc{} || len_result.ec != std::errc{}) {
      send_error(detail::gdb_errno::gdb_EINVAL);
      return gdb_action::none;
    }

    GDBSTUB_LOG("[CMD X] Writing binary memory at 0x%zx, length %zu", addr, len);
    std::vector<char> data(args.begin() + colon_pos + 1, args.end());
    size_t actual_len = detail::unescape_binary(data.data(), data.size());

    if (actual_len != len) {
      send_error(detail::gdb_errno::gdb_EINVAL);
      return gdb_action::none;
    }

    if (target_.write_mem(addr, len, data.data()) != 0) {
      send_error(detail::gdb_errno::gdb_EFAULT);
      return gdb_action::none;
    }

    send_packet("OK");
    return gdb_action::none;
  }

  gdb_action handle_continue(std::string_view args) {
    GDBSTUB_LOG("[CMD c] Continue execution (address arg ignored)");
    async_io_enabled_.store(true, std::memory_order_relaxed);
    if (on_continue) {
      on_continue();
    }

    auto action = target_.cont();

    async_io_enabled_.store(false, std::memory_order_relaxed);
    if (action == gdb_action::stop) {
      send_stop_reply();
      if (on_break) {
        on_break();
      }
    }
    return action;
  }

  gdb_action handle_step(std::string_view args) {
    GDBSTUB_LOG("[CMD s] Step one instruction (address arg ignored)");
    if (on_continue) {
      on_continue();
    }

    auto action = target_.stepi();

    if (action == gdb_action::stop) {
      send_stop_reply();
      if (on_break) {
        on_break();
      }
    }
    return action;
  }

  std::optional<std::tuple<int, size_t, size_t>> parse_breakpoint_packet(std::string_view args) {
    auto first_comma = args.find(',');
    if (first_comma == std::string_view::npos) {
      return std::nullopt;
    }
    auto second_comma = args.find(',', first_comma + 1);
    if (second_comma == std::string_view::npos) {
      return std::nullopt;
    }

    int type;
    size_t addr, kind;

    auto type_result = std::from_chars(args.data(), args.data() + first_comma, type);
    auto addr_result = std::from_chars(args.data() + first_comma + 1, args.data() + second_comma, addr, 16);
    auto kind_result = std::from_chars(args.data() + second_comma + 1, args.data() + args.size(), kind, 16);

    if (type_result.ec != std::errc{} || addr_result.ec != std::errc{} || kind_result.ec != std::errc{}) {
      return std::nullopt;
    }
    return std::make_tuple(type, addr, kind);
  }

  gdb_action handle_insert_breakpoint(std::string_view args) {
    if constexpr (detail::has_breakpoints_v<Target>) {
      auto bp = parse_breakpoint_packet(args);
      if (!bp) {
        send_error(detail::gdb_errno::gdb_EINVAL);
        return gdb_action::none;
      }
      auto [type, addr, kind] = *bp;
      (void) kind; // kind is unused for now but part of the protocol
      GDBSTUB_LOG("[CMD Z] Insert breakpoint type %d at 0x%zx", type, addr);
      bool ok = target_.set_breakpoint(addr, static_cast<breakpoint_type>(type));
      GDBSTUB_LOG("[CMD Z] Result: %s", ok ? "OK" : "Error");
      send_packet(ok ? "OK" : ""); // Empty string for not supported, OK for success
    } else {
      GDBSTUB_LOG("[CMD Z] Not supported by target");
      send_packet("");
    }
    return gdb_action::none;
  }

  gdb_action handle_remove_breakpoint(std::string_view args) {
    if constexpr (detail::has_breakpoints_v<Target>) {
      auto bp = parse_breakpoint_packet(args);
      if (!bp) {
        send_error(detail::gdb_errno::gdb_EINVAL);
        return gdb_action::none;
      }
      auto [type, addr, kind] = *bp;
      (void) kind; // kind is unused for now but part of the protocol
      GDBSTUB_LOG("[CMD z] Remove breakpoint type %d at 0x%zx", type, addr);
      bool ok = target_.del_breakpoint(addr, static_cast<breakpoint_type>(type));
      GDBSTUB_LOG("[CMD z] Result: %s", ok ? "OK" : "Error");
      send_packet(ok ? "OK" : "");
    } else {
      GDBSTUB_LOG("[CMD z] Not supported by target");
      send_packet("");
    }
    return gdb_action::none;
  }

  gdb_action handle_query(std::string_view args) {
    auto colon_pos = args.find(':');
    auto query_name = colon_pos != std::string_view::npos ? args.substr(0, colon_pos) : args;

    GDBSTUB_LOG("[CMD q] Query: '%.*s'", static_cast<int>(query_name.size()), query_name.data());

    if (query_name == "Supported") {
      std::string features;
      char buf[64];
      snprintf(buf, sizeof(buf), "PacketSize=%zx;vContSupported+", detail::MAX_PACKET_SIZE);
      features = buf;

      if (arch_.target_desc && arch_.xml_architecture_name) {
        features += ";qXfer:features:read+;xmlRegisters=";
        features += arch_.xml_architecture_name;
      }
      if constexpr (detail::has_breakpoints_v<Target>) {
        features += ";swbreak+;hwbreak+";
      }
      if constexpr (detail::has_register_info_v<Target>) {
        features += ";qRegisterInfo+";
      }
      if (args.find("QStartNoAckMode+") != std::string_view::npos) {
        features += ";QStartNoAckMode+";
      }
      send_packet(features);
    } else if (query_name == "Attached") {
      send_packet("1"); // We are always attached to an existing process.
    } else if (query_name == "C") {
      char buf[16];
      int current_cpu = 0;
      if constexpr (detail::has_cpu_ops_v<Target>) {
        current_cpu = target_.get_cpu();
      }
      snprintf(buf, sizeof(buf), "QC%x", current_cpu + 1); // GDB threads are 1-based
      send_packet(buf);
    } else if (query_name == "fThreadInfo") {
      std::string response = "m";
      for (int i = 0; i < arch_.cpu_count; ++i) {
        if (i > 0) {
          response += ',';
        }
        char buf[8];
        snprintf(buf, sizeof(buf), "%x", i + 1);
        response += buf;
      }
      send_packet(response);
    } else if (query_name == "sThreadInfo") {
      send_packet("l"); // 'l' for last/end of list.
    } else if (query_name == "Symbol") {
      send_packet("OK");
    } else if (query_name == "Xfer") {
      handle_xfer(args.substr(5)); // Skip "Xfer:"
    } else if (query_name == "HostInfo") {
      handle_host_info();
    } else if (query_name == "MemoryRegionInfo") {
      handle_memory_region_info(args.substr(17)); // Skip "MemoryRegionInfo:"
    } else if (query_name.rfind("RegisterInfo", 0) == 0) {
      handle_register_info(query_name.substr(12)); // Skip "RegisterInfo"
    } else {
      GDBSTUB_LOG("[CMD q] Unsupported query: '%.*s'", static_cast<int>(query_name.size()), query_name.data());
      send_packet("");
    }

    return gdb_action::none;
  }

  gdb_action handle_set_query(std::string_view args) {
    GDBSTUB_LOG("[CMD Q] Set: '%.*s'", static_cast<int>(args.size()), args.data());
    if (args == "StartNoAckMode") {
      no_ack_mode_ = true;
      GDBSTUB_LOG("[SERVER] No-ACK mode enabled.");
      send_packet("OK");
    } else {
      send_packet("");
    }
    return gdb_action::none;
  }

  void handle_xfer(std::string_view args) {
    if (args.rfind("features:read:target.xml:", 0) != 0) {
      send_packet("");
      return;
    }
    if (!arch_.target_desc) {
      send_packet("E01");
      return;
    }

    auto offset_str = args.substr(25);
    auto comma_pos = offset_str.find(',');
    if (comma_pos == std::string_view::npos) {
      send_packet("E01");
      return;
    }

    size_t offset, length;
    auto offset_result = std::from_chars(offset_str.data(), offset_str.data() + comma_pos, offset, 16);
    auto length_result =
        std::from_chars(offset_str.data() + comma_pos + 1, offset_str.data() + offset_str.size(), length, 16);

    if (offset_result.ec != std::errc{} || length_result.ec != std::errc{}) {
      send_packet("E01");
      return;
    }

    GDBSTUB_LOG("[XFER] Read target.xml, offset=%zu, len=%zu", offset, length);
    std::string_view desc(arch_.target_desc);
    if (offset >= desc.size()) {
      send_packet("l"); // 'l' indicates end of data.
      return;
    }

    size_t to_send = std::min(length, desc.size() - offset);
    std::string response;
    response.reserve(to_send + 1);
    response += (offset + to_send >= desc.size()) ? 'l' : 'm';
    response.append(desc.data() + offset, to_send);
    send_packet(response);
  }

  void handle_host_info() {
    if constexpr (detail::has_host_info_v<Target>) {
      GDBSTUB_LOG("[qHostInfo] Responding with host info.");
      auto info = target_.get_host_info();
      char buf[256];
      snprintf(buf, sizeof(buf), "triple:%s;endian:%s;ptrsize:%d;", info.triple, info.endian, info.ptr_size);
      send_packet(buf);
    } else {
      GDBSTUB_LOG("[qHostInfo] Not supported by target.");
      send_packet("");
    }
  }

  void handle_memory_region_info(std::string_view addr_str) {
    if constexpr (detail::has_mem_region_info_v<Target>) {
      size_t addr;
      auto result = std::from_chars(addr_str.data(), addr_str.data() + addr_str.size(), addr, 16);
      if (result.ec != std::errc{}) {
        send_error(detail::gdb_errno::gdb_EINVAL);
        return;
      }

      GDBSTUB_LOG("[qMemoryRegionInfo] Query for address 0x%zx", addr);
      auto region = target_.get_mem_region_info(addr);
      if (region && region->size > 0) {
        char buf[256];
        snprintf(
            buf, sizeof(buf), "start:%zx;size:%zx;permissions:%s;", region->start, region->size, region->permissions
        );
        send_packet(buf);
      } else {
        send_error(detail::gdb_errno::gdb_EFAULT);
      }
    } else {
      GDBSTUB_LOG("[qMemoryRegionInfo] Not supported by target.");
      send_packet("");
    }
  }

  void handle_register_info(std::string_view regno_str) {
    if constexpr (detail::has_register_info_v<Target>) {
      int regno;
      auto result = std::from_chars(regno_str.data(), regno_str.data() + regno_str.size(), regno, 16);
      if (result.ec != std::errc{} || regno < 0 || regno >= arch_.reg_count) {
        send_error(detail::gdb_errno::gdb_EINVAL);
        return;
      }
      GDBSTUB_LOG("[qRegisterInfo] Query for register %d", regno);
      auto info = target_.get_register_info(regno);
      if (!info) {
        send_error(detail::gdb_errno::gdb_EFAULT);
        return;
      }

      std::string response;
      char buf[512];
      snprintf(
          buf, sizeof(buf), "name:%s;bitsize:%d;offset:%d;encoding:%s;format:%s;set:%s;", info->name, info->bitsize,
          info->offset, info->encoding, info->format, info->set
      );
      response += buf;
      if (info->alt_name) {
        snprintf(buf, sizeof(buf), "alt-name:%s;", info->alt_name);
        response += buf;
      }
      if (info->dwarf_regnum != -1) {
        snprintf(buf, sizeof(buf), "dwarf_regno:%d;", info->dwarf_regnum);
        response += buf;
      }
      if (info->generic) {
        snprintf(buf, sizeof(buf), "generic:%s;", info->generic);
        response += buf;
      }

      send_packet(response);
    } else {
      GDBSTUB_LOG("[qRegisterInfo] Not supported by target.");
      send_packet("");
    }
  }

  gdb_action handle_v_packet(std::string_view args) {
    auto semicolon_pos = args.find(';');
    auto question_pos = args.find('?');
    auto cmd_end = std::min(semicolon_pos, question_pos);
    auto cmd_name = args.substr(0, cmd_end);

    GDBSTUB_LOG("[CMD v] Packet: '%.*s'", static_cast<int>(cmd_name.size()), cmd_name.data());
    if (cmd_name == "Cont?") {
      send_packet("vCont;c;C;s;S");
    } else if (cmd_name == "Cont") {
      auto action_str = args.substr(cmd_name.size() + 1);
      if (action_str.empty()) {
        send_error(detail::gdb_errno::gdb_EINVAL);
        return gdb_action::none;
      }
      char action_char = action_str[0];
      if (action_char == 'c' || action_char == 'C') {
        return handle_continue(action_str);
      } else if (action_char == 's' || action_char == 'S') {
        return handle_step(action_str);
      } else {
        send_error(detail::gdb_errno::gdb_EINVAL);
      }
    } else {
      send_packet("");
    }
    return gdb_action::none;
  }

  gdb_action handle_set_thread(std::string_view args) {
    GDBSTUB_LOG("[CMD H] Set thread '%.*s'", static_cast<int>(args.size()), args.data());
    if (args.size() > 1 && args[0] == 'g') {
      if constexpr (detail::has_cpu_ops_v<Target>) {
        int cpu_id;
        auto thread_str = args.substr(1);
        auto result = std::from_chars(thread_str.data(), thread_str.data() + thread_str.size(), cpu_id, 16);
        if (result.ec != std::errc{}) {
          send_error(detail::gdb_errno::gdb_EINVAL);
          return gdb_action::none;
        }
        cpu_id -= 1; // GDB is 1-based, we are 0-based
        if (cpu_id >= 0 && cpu_id < arch_.cpu_count) {
          target_.set_cpu(cpu_id);
        } else if (cpu_id == -2) { // -1 in GDB is "all threads"
          target_.set_cpu(0);      // Default to CPU 0
        }
      }
    }
    send_packet("OK");
    return gdb_action::none;
  }

  gdb_action handle_thread_alive(std::string_view args) {
    GDBSTUB_LOG("[CMD T] Thread alive? '%.*s'", static_cast<int>(args.size()), args.data());
    send_packet("OK");
    return gdb_action::none;
  }

  gdb_action handle_halt_reason() {
    GDBSTUB_LOG("[CMD ?] Halt reason requested.");
    send_stop_reply();
    return gdb_action::none;
  }

  gdb_action handle_detach() {
    GDBSTUB_LOG("[CMD D] Detach requested. Shutting down.");
    send_packet("OK");
    return gdb_action::shutdown;
  }

  gdb_action handle_extended_mode() {
    GDBSTUB_LOG("[CMD !] Extended mode enabled.");
    send_packet("OK");
    return gdb_action::none;
  }

  /**
   * @brief Send a stop reply packet to the debugger.
   *
   * This packet informs the debugger that the target has stopped.
   * The format is T<signal_hex_val><key>:<val>;...
   * Including the thread and PC is a major performance optimization.
   */
  void send_stop_reply() {
    char buf[128];
    int current_cpu = 0;
    if constexpr (detail::has_cpu_ops_v<Target>) {
      current_cpu = target_.get_cpu();
    }

    snprintf(buf, sizeof(buf), "T%02xthread:%x;", static_cast<int>(gdb_signal::trap), current_cpu + 1);
    std::string reply = buf;

    if (arch_.pc_reg_num != -1) {
      size_t pc_size = target_.reg_size(arch_.pc_reg_num);
      if (pc_size > 0 && pc_size <= detail::MAX_REG_SIZE) {
        ensure_buffer_size(reg_buffer_, pc_size);
        if (target_.read_reg(arch_.pc_reg_num, reg_buffer_.data()) == 0) {
          ensure_buffer_size(hex_buffer_, pc_size * 2 + 1);
          detail::bytes_to_hex(reg_buffer_.data(), pc_size, hex_buffer_.data());

          snprintf(buf, sizeof(buf), "%x:%.*s;", arch_.pc_reg_num, static_cast<int>(pc_size * 2), hex_buffer_.data());
          reply += buf;
        }
      }
    }
    GDBSTUB_LOG("[EVENT] Target stopped. Sending stop reply: %s", reply.c_str());
    send_packet(reply);
  }
};

// =============================================================================
// Convenience functions for simple usage patterns
// =============================================================================

/**
 * @brief Simple blocking serve function (integration pattern 1).
 *
 * @param target The target system to debug.
 * @param arch Architecture description of the target.
 * @param address Listen address (e.g., "localhost:1234").
 */
template <typename Target> void serve(Target& target, const arch_info& arch, const char* address) {
  server<Target> stub(target, arch);
  if (!stub.listen(address)) {
    throw std::runtime_error("failed to listen on address");
  }
  stub.serve_forever();
}

/**
 * @brief Create a TCP server instance for more advanced usage patterns.
 */
template <typename Target> auto make_tcp_server(Target& target, const arch_info& arch) {
  return std::make_unique<server<Target, tcp_transport>>(target, arch);
}

#ifndef _WIN32
/**
 * @brief Create a Unix domain socket server instance for more advanced usage patterns.
 */
template <typename Target> auto make_unix_server(Target& target, const arch_info& arch) {
  return std::make_unique<server<Target, unix_transport>>(target, arch);
}
#endif

} // namespace gdbstub