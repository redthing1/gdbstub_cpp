/**
 * gdbstub.d - A modern D header-only GDB Remote Serial Protocol implementation
 *
 * This library provides a complete implementation of the GDB Remote Serial Protocol,
 * allowing emulators and embedded systems to be debugged using GDB and LLDB.
 *
 *
 * Features:
 * - Header-only, no dependencies beyond standard D
 * - Supports incremental functionality (compile-time feature detection)
 * - Three integration patterns: blocking, polling, and callback-based
 * - Cross-platform (Windows/Linux/macOS)
 * - Memory efficient with reusable buffers
 * - Full protocol compliance
 *
 * Basic usage:
 * ```d
 * import gdbstub;
 * import std.typecons : Nullable, nullable;
 *
 * struct MyEmulator {
 *     // Required methods
 *     Nullable!stop_reason cont() { ... }
 *     Nullable!stop_reason stepi() { ... }
 *     size_t reg_size(int regno) const { ... }
 *     int read_reg(int regno, ubyte[] data) { ... }
 *     int write_reg(int regno, const(ubyte)[] data) { ... }
 *     int read_mem(size_t addr, size_t len, ubyte[] data) { ... }
 *     int write_mem(size_t addr, size_t len, const(ubyte)[] data) { ... }
 *
 *     // Optional methods (detected automatically)
 *     // Nullable!register_info get_register_info(int regno) { ... }
 *     // bool set_breakpoint(size_t addr, breakpoint_type type) { ... }
 *     // bool del_breakpoint(size_t addr, breakpoint_type type) { ... }
 *     // Nullable!host_info get_host_info() { ... }
 *     // Nullable!process_info get_process_info() { ... }
 *     // Nullable!mem_region get_mem_region_info(size_t addr) { ... }
 *     // void on_interrupt() { ... }
 * };
 *
 * // --- To enable writable registers with LLDB, you MUST use the target.xml ---
 * immutable string my_target_xml = "<?xml ... </target>"; // See GDB docs for format
 *
 * auto emu = MyEmulator();
 * auto arch = arch_info(
 *   // By providing a target_desc, you enable the modern qXfer:features:read protocol.
 *   my_target_xml,
 *   "org.gnu.gdb.riscv.cpu", // Must match a <feature> in the XML
 *
 *   "bare", // osabi
 *   33, // reg_count
 *   32  // pc_reg_num
 * );
 * gdbstub.serve(emu, arch, "localhost:1234");
 * ```
 */

module gdbstub;

import core.atomic;
import core.stdc.stdio;
import core.stdc.string;
import core.time;
import std.algorithm.comparison : min;
import std.algorithm.mutation : reverse;
import std.algorithm.searching : find;
import std.array : appender;
import std.conv : to, parse;
import std.format : format;
import std.exception : enforce;
import std.socket; // <-- Use the high-level socket library

// Helper function for socket error handling
bool wouldHaveBlocked() {
    version (Windows) {
        import core.sys.windows.winsock2;
        return WSAGetLastError() == WSAEWOULDBLOCK;
    } else {
        import core.stdc.errno;
        return errno == EAGAIN || errno == EWOULDBLOCK;
    }
}
import std.string;
import std.typecons : Nullable, nullable, Tuple, tuple;
import std.traits;
import std.meta : AliasSeq;

// Optional GDB remote serial protocol debugging
// Compile with -version=GDBSTUB_DEBUG to enable packet-level debugging output
version (GDBSTUB_DEBUG) {
    void GDBSTUB_LOG(A...)(string fmt, A args) {
        import std.stdio : writef, writeln;
        writef("[GDBSTUB] " ~ fmt ~ "\n", args);
    }
} else {
    void GDBSTUB_LOG(A...)(string fmt, A args) {}
}

// =============================================================================
// Core types and constants
// =============================================================================

/**
 * @brief Actions that target operations can return to control debugger flow.
 * @deprecated This is now internal. The public API uses std.typecons.Nullable!stop_reason.
 */
enum gdb_action {
    none,    ///< No special action, continue debugging normally
    stop,    ///< Target hit breakpoint or completed step, send stop reply
    shutdown ///< Target wants to terminate debugging session
}

/**
 * @brief GDB/Unix signal numbers for use in stop replies.
 */
enum gdb_signal : int {
    OK = 0,    ///< Used for successful command completion
    TRAP = 5,  ///< Trace/breakpoint trap (standard for breakpoints)
    INT = 2,   ///< Interrupt (e.g., from Ctrl-C)
    ILL = 4,   ///< Illegal instruction
    FPE = 8,   ///< Floating point exception
    BUS = 10,  ///< Bus error
    SEGV = 11, ///< Segmentation fault
}

/**
 * @brief The reason the target stopped, returned by execution commands.
 */
enum stop_type {
    signal,       ///< Halted due to a signal (e.g., illegal instruction)
    sw_break,     ///< Halted due to a software breakpoint
    hw_break,     ///< Halted due to a hardware breakpoint
    write_watch,  ///< Halted due to a write watchpoint
    read_watch,   ///< Halted due to a read watchpoint
    access_watch, ///< Halted due to an access watchpoint
}

/**
 * @brief Describes a stop event in the target.
 * This struct is returned by the Target's cont() and stepi() methods.
 */
struct stop_reason {
    stop_type type = stop_type.signal;
    /// For `signal` type, this is the `gdb_signal` value.
    /// For all other types, it is ignored (signal defaults to TRAP).
    gdb_signal signal = gdb_signal.TRAP;
    /// For watchpoint types, this is the address that was accessed.
    size_t addr = 0;
}

/**
 * @brief Breakpoint types supported by the GDB protocol.
 */
enum breakpoint_type : int {
    software = 0,         ///< Software breakpoint (e.g., BKPT instruction)
    hardware = 1,         ///< Hardware breakpoint
    write_watchpoint = 2, ///< Break on memory write
    read_watchpoint = 3,  ///< Break on memory read
    access_watchpoint = 4 ///< Break on memory access (read or write)
}

/**
 * @brief Architecture description for the target system.
 */
struct arch_info {
    /// The full XML content for GDB's target description.
    /// Providing this enables the modern `qXfer:features:read` protocol.
    string target_desc = null;

    /// The name GDB/LLDB uses to identify the register set in the XML.
    /// Must match a <feature name="..."> in your target_desc XML.
    /// e.g., "org.gnu.gdb.riscv.cpu".
    string xml_architecture_name = null;

    /// Optional OS ABI string, e.g., "GNU/Linux", "bare".
    string osabi = null;

    int cpu_count = 1;   ///< Number of CPUs/cores for SMP systems.
    int reg_count = 0;   ///< Number of registers in the target architecture.
    int pc_reg_num = -1; ///< Register number of the Program Counter (PC).

    bool swap_registers_endianness = false; ///< Byte-swap register data in GDB packets.
}

/**
 * @brief Information about the host system, for `qHostInfo`.
 */
struct host_info {
    string triple = "unknown-unknown-unknown"; ///< Target triple.
    string endian = "little";                  ///< "little", "big", or "pdp".
    int ptr_size = 0;                          ///< Pointer size in bytes.
    string hostname = "gdbstub";               ///< Hostname of the target.
    string os_version = null;                  ///< OS version string.
    string os_build = null;                    ///< OS build string.
    string os_kernel = null;                   ///< OS kernel string.
}

/**
 * @brief Information about the running process, for `qProcessInfo`.
 */
struct process_info {
    int pid;                                   ///< Process ID.
    string triple = "unknown-unknown-unknown"; ///< Target triple.
    string endian = "little";                  ///< "little" or "big".
    string ostype = "unknown";                 ///< OS type string.
    int ptr_size = 0;                          ///< Pointer size in bytes.
}

/**
 * @brief Describes a region of memory for the `qMemoryRegionInfo` packet.
 */
struct mem_region {
    size_t start;       ///< Start address of the region.
    size_t size;        ///< Size of the region in bytes.
    string permissions; ///< Permissions string, e.g., "r", "rw", "rx".
}

/**
 * @brief Detailed information about a single register, for `qRegisterInfo`.
 *
 * The `offset` field must be the byte offset of this register within the 'g' packet response.
 */
struct register_info {
    string name = "unknown";                  ///< e.g., "x0", "pc", "sp"
    string alt_name = null;                   ///< e.g., "zero" for x0
    string set = "General Purpose Registers"; ///< Register set name
    string generic = null;                    ///< Generic name like "pc", "sp", "fp", "ra"
    string encoding = "uint";                 ///< "uint", "ieee754", "vector"
    string format = "hex";                    ///< "hex", "decimal", "float"
    int bitsize = 0;                          ///< Size of the register in bits
    int offset = 0;                           ///< Offset in the 'g' packet
    int dwarf_regnum = -1;                    ///< DWARF register number
}

// =============================================================================
// Implementation details
// =============================================================================

private {

// GDB protocol error codes (subset of standard errno values)
enum gdb_errno : int {
    gdb_EPERM = 0x01,  ///< Operation not permitted
    gdb_ENOENT = 0x02, ///< No such file or directory
    gdb_EINTR = 0x04,  ///< Interrupted system call
    gdb_EBADF = 0x09,  ///< Bad file number
    gdb_EACCES = 0x0D, ///< Permission denied
    gdb_EFAULT = 0x0E, ///< Bad address
    gdb_EBUSY = 0x10,  ///< Device or resource busy
    gdb_EINVAL = 0x16, ///< Invalid argument
    gdb_ENOSPC = 0x1c, ///< No space left on device
}

// Protocol constants
enum : size_t {
    MAX_PACKET_SIZE = 4096,        ///< Maximum packet size we support.
    MAX_MEMORY_READ = 2048,        ///< Maximum memory read size per packet.
    MAX_REG_SIZE = 256,            ///< Maximum register size in bytes.
    PACKET_GARBAGE_THRESHOLD = 16, ///< Buffer size before clearing garbage.
    PACKET_OVERHEAD_SIZE = 16,     ///< Estimated packet overhead for transfers.
}

// Hex conversion utilities
immutable char[] hex_chars = "0123456789abcdef";

/**
 * @brief Convert a hex character to its numeric value.
 */
ubyte hex_to_nibble(char c) {
    if (c >= '0' && c <= '9') {
        return cast(ubyte)(c - '0');
    }
    if (c >= 'a' && c <= 'f') {
        return cast(ubyte)(c - 'a' + 10);
    }
    if (c >= 'A' && c <= 'F') {
        return cast(ubyte)(c - 'A' + 10);
    }
    return 0xff; // Invalid hex char
}

/**
 * @brief Convert binary data to hex string.
 */
void bytes_to_hex(const(void)* bytes, size_t len, char* hex) {
    const(ubyte)* p = cast(const(ubyte)*) bytes;
    for (size_t i = 0; i < len; ++i) {
        hex[i * 2] = hex_chars[p[i] >> 4];
        hex[i * 2 + 1] = hex_chars[p[i] & 0xf];
    }
    hex[len * 2] = '\0';
}

/**
 * @brief Convert hex string to binary data.
 */
bool hex_to_bytes(const(char)* hex, size_t hex_len, void* bytes) {
    if (hex_len % 2 != 0) {
        return false;
    }

    ubyte* p = cast(ubyte*) bytes;
    for (size_t i = 0; i < hex_len; i += 2) {
        ubyte high = hex_to_nibble(hex[i]);
        ubyte low = hex_to_nibble(hex[i + 1]);
        if (high == 0xff || low == 0xff) {
            return false;
        }
        p[i / 2] = cast(ubyte)((high << 4) | low);
    }
    return true;
}

/**
 * @brief Compute GDB packet checksum.
 */
ubyte compute_checksum(string data) {
    ubyte sum = 0;
    foreach (char c; data) {
        sum += cast(ubyte) c;
    }
    return sum;
}

/**
 * @brief Unescape binary data in 'X' packets ('}' followed by char XOR 0x20).
 */
size_t unescape_binary(char[] data) {
    char* write_ptr = data.ptr;
    char* read_ptr = data.ptr;
    char* end = data.ptr + data.length;

    while (read_ptr < end) {
        if (*read_ptr == '}' && read_ptr + 1 < end) {
            *write_ptr++ = *(read_ptr + 1) ^ 0x20;
            read_ptr += 2;
        } else {
            *write_ptr++ = *read_ptr++;
        }
    }
    return write_ptr - data.ptr;
}

/**
 * @brief Byte-swap a region of memory in place.
 */
void swap_bytes(void* data, size_t size) {
    if (size > 1) {
        ubyte* p = cast(ubyte*) data;
        reverse(p[0 .. size]);
    }
}

// SFINAE helpers for detecting optional target methods
// D's version is much cleaner using `__traits(compiles)`.
enum bool has_breakpoints(T) = __traits(compiles, {
    T t;
    t.set_breakpoint(0, breakpoint_type.software);
    t.del_breakpoint(0, breakpoint_type.software);
});

enum bool has_cpu_ops(T) = __traits(compiles, {
    T t;
    t.set_cpu(0);
    (cast(const(T)) t).get_cpu();
});

enum bool has_interrupt(T) = __traits(compiles, (T t) => t.on_interrupt());
enum bool has_host_info(T) = __traits(compiles, (T t) => t.get_host_info());
enum bool has_mem_region_info(T) = __traits(compiles, (T t) => t.get_mem_region_info(0));
enum bool has_register_info(T) = __traits(compiles, (T t) => t.get_register_info(0));
enum bool has_process_info(T) = __traits(compiles, (T t) => t.get_process_info());

} // private

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
    enum size_t initial_capacity = 1024;

    char[] buffer_;
    size_t size_ = 0;
    Nullable!size_t packet_end_;
    bool ack_sent_ = false;

public:
    this() {
        buffer_.length = initial_capacity;
    }

    /**
     * @brief Append data received from the transport layer.
     */
    void append(const(char)[] data) {
        if (size_ + data.length > buffer_.length) {
            buffer_.length = (size_ + data.length) * 2;
        }
        memcpy(buffer_.ptr + size_, data.ptr, data.length);
        size_ += data.length;
    }

    /**
     * @brief Check if the buffer contains a complete packet.
     * A complete packet has the format: $<data>#<2-digit-checksum>
     */
    bool has_complete_packet() {
        if (!packet_end_.isNull) {
            return true;
        }

        // Find packet start ($)
        auto start_ptr = find(buffer_[0 .. size_], '$').ptr;
        if (start_ptr == buffer_.ptr + size_) {
            // No packet start found - keep a reasonable tail in case '$' arrives later
            if (size_ > PACKET_GARBAGE_THRESHOLD) {
                size_ = 0; // Clear if we have too much garbage
            }
            return false;
        }

        // Shift buffer to start at packet
        if (start_ptr != buffer_.ptr) {
            size_t offset = start_ptr - buffer_.ptr;
            memmove(buffer_.ptr, start_ptr, size_ - offset);
            size_ -= offset;
        }

        // Find packet end (#)
        auto end_ptr = find(buffer_[0 .. size_], '#').ptr;
        if (end_ptr == buffer_.ptr + size_) {
            return false; // Incomplete packet
        }

        // Check if we have checksum (2 chars after #)
        size_t payload_end = end_ptr - buffer_.ptr;
        if (size_ < payload_end + 3) { // # + 2 checksum chars
            return false;
        }

        packet_end_ = payload_end + 3;
        return true;
    }

    /**
     * @brief Check if an ACK needs to be sent for the current packet.
     */
    bool needs_ack() const { return !packet_end_.isNull && !ack_sent_; }

    /**
     * @brief Mark that an ACK has been sent for the current packet.
     */
    void mark_ack_sent() { ack_sent_ = true; }

    /**
     * @brief Get the complete packet including frame ($...#XX).
     */
    string get_packet() const {
        if (packet_end_.isNull) {
            return null;
        }
        return cast(string) buffer_[0 .. packet_end_.get];
    }

    /**
     * @brief Get the packet payload (data between $ and #).
     */
    string get_payload() const {
        if (packet_end_.isNull || packet_end_.get < 4) {
            return null;
        }
        return cast(string) buffer_[1 .. packet_end_.get - 3];
    }

    /**
     * @brief Verify the checksum of the current packet.
     */
    bool verify_checksum() const {
        if (packet_end_.isNull) {
            return false;
        }

        auto payload = get_payload();
        auto packet = get_packet();

        ubyte expected;
        if (!hex_to_bytes(packet.ptr + packet.length - 2, 2, &expected)) {
            return false;
        }

        return compute_checksum(payload) == expected;
    }

    /**
     * @brief Remove the current processed packet from the buffer.
     */
    void consume_packet() {
        if (packet_end_.isNull) {
            return;
        }

        size_t end = packet_end_.get;
        size_t remaining = size_ - end;
        if (remaining > 0) {
            memmove(buffer_.ptr, buffer_.ptr + end, remaining);
        }
        size_ = remaining;
        packet_end_.nullify();
        ack_sent_ = false;
    }

    /**
     * @brief Clear the buffer for reuse.
     */
    void clear() {
        size_ = 0;
        packet_end_.nullify();
        ack_sent_ = false;
    }

    /**
     * @brief Build a GDB packet with a calculated checksum.
     */
    string build_packet(string data) {
        clear();

        // Ensure capacity
        size_t needed = data.length + 4; // $data#XX
        if (buffer_.length < needed) {
            buffer_.length = needed;
        }

        // Build packet: $<data>#<checksum>
        buffer_[0] = '$';
        memcpy(buffer_.ptr + 1, data.ptr, data.length);
        buffer_[data.length + 1] = '#';

        // Add 2-digit hex checksum
        ubyte checksum = compute_checksum(data);
        buffer_[data.length + 2] = hex_chars[checksum >> 4];
        buffer_[data.length + 3] = hex_chars[checksum & 0xf];

        size_ = data.length + 4;
        return cast(string) buffer_[0 .. size_];
    }
}

// =============================================================================
// Transport layer abstraction
// =============================================================================

/**
 * @brief TCP transport for network debugging.
 */
class tcp_transport {
    Socket listen_sock_;
    Socket conn_sock_;

public:
    this() {}

    /**
     * @brief Listen on a TCP address.
     * @param address Format: "host:port", e.g., "localhost:1234" or "*:1234".
     */
    bool listen(string address) {
        GDBSTUB_LOG("[TCP] Starting server on %s", address.ptr);
        try {
            auto colon_pos = address.lastIndexOf(':');
            if (colon_pos < 0) {
                GDBSTUB_LOG("[ERROR] Invalid TCP address format: %s", address.ptr);
                return false;
            }

            string host = address[0 .. colon_pos];
            string port_str = address[colon_pos + 1 .. $];

            if (host == "*" || host.length == 0) {
                // getAddress does not handle "*", so we use a passive address
                ushort port = to!ushort(port_str);
                auto addr = new InternetAddress(port); // Binds to INADDR_ANY
                listen_sock_ = new TcpSocket(addr.addressFamily);
                listen_sock_.setOption(SocketOptionLevel.SOCKET, SocketOption.REUSEADDR, 1);
                listen_sock_.bind(addr);
            } else {
                auto results = getAddress(host, port_str);
                if (results.length == 0) {
                     GDBSTUB_LOG("[ERROR] Could not resolve address: %s", address.ptr);
                     return false;
                }
                listen_sock_ = new TcpSocket(results[0].addressFamily);
                listen_sock_.setOption(SocketOptionLevel.SOCKET, SocketOption.REUSEADDR, 1);
                listen_sock_.bind(results[0]);
            }
            
            listen_sock_.listen(1);
            return true;
        } catch (SocketException e) {
            GDBSTUB_LOG("[ERROR] Socket listen failed: %s", e.msg.ptr);
            return false;
        }
    }

    /**
     * @brief Accept an incoming connection.
     */
    bool accept() {
        GDBSTUB_LOG("[TCP] Waiting for debugger connection...");
        try {
            conn_sock_ = listen_sock_.accept();
            GDBSTUB_LOG("[TCP] Debugger connected.");
            return true;
        } catch (SocketException e) {
            GDBSTUB_LOG("[ERROR] Failed to accept connection: %s", e.msg.ptr);
            return false;
        }
    }

    bool connected() const { return conn_sock_ !is null && conn_sock_.isAlive; }

    ptrdiff_t read(void* buf, size_t len) {
        try {
            auto slice = (cast(ubyte*)buf)[0 .. len];
            auto received = conn_sock_.receive(slice);
            if (received == Socket.ERROR) {
                return -1; // Indicate a real error/disconnect
            }
            return received;
        } catch (SocketException e) {
            return -1;
        }
    }

    ptrdiff_t write(const(void)* buf, size_t len) {
        try {
            size_t total = 0;
            auto slice = (cast(const(ubyte)*)buf)[0 .. len];
            while (total < len) {
                ptrdiff_t n = conn_sock_.send(slice[total .. $]);
                if (n == Socket.ERROR) {
                    return total > 0 ? total : -1;
                }
                if (n == 0) break; // Connection closed
                total += n;
            }
            return total;
        } catch (SocketException e) {
            return -1;
        }
    }

    bool readable(int timeout_ms = 0) {
        if (!connected()) return false;
        try {
            auto readSet = new SocketSet();
            readSet.add(conn_sock_);
            
            if (timeout_ms < 0) {
                // Blocking mode - wait indefinitely
                return Socket.select(readSet, null, null) > 0;
            } else if (timeout_ms == 0) {
                // Non-blocking mode
                return Socket.select(readSet, null, null, dur!"msecs"(0)) > 0;
            } else {
                // Timed wait
                return Socket.select(readSet, null, null, dur!"msecs"(timeout_ms)) > 0;
            }
        } catch (SocketException e) {
            return false;
        }
    }

    void disconnect() {
        if (conn_sock_) conn_sock_.close();
    }

    void close() {
        disconnect();
        if (listen_sock_) listen_sock_.close();
    }
}

// Unix domain socket transport (not available on Windows)
version (Posix) {
    /**
     * @brief Unix domain socket transport for local debugging.
     */
    class unix_transport {
        Socket listen_sock_;
        Socket conn_sock_;
        string path_;

    public:
        this() {}
        ~this() {
            close();
        }

        /**
         * @brief Listen on a Unix domain socket path.
         */
        bool listen(string path) {
            GDBSTUB_LOG("[UNIX] Starting server on %s", path.ptr);
            path_ = path;
            try {
                // Manually unlink previous socket if it exists
                import core.sys.posix.unistd : unlink;
                unlink(path.ptr);

                auto addr = new UnixAddress(path);
                listen_sock_ = new Socket(AddressFamily.UNIX, SocketType.STREAM);
                listen_sock_.bind(addr);
                listen_sock_.listen(1);
                return true;
            } catch (SocketException e) {
                GDBSTUB_LOG("[ERROR] Unix socket listen failed: %s", e.msg.ptr);
                return false;
            }
        }

        bool accept() {
            GDBSTUB_LOG("[UNIX] Waiting for debugger connection...");
            try {
                conn_sock_ = listen_sock_.accept();
                GDBSTUB_LOG("[UNIX] Debugger connected.");
                return true;
            } catch (SocketException e) {
                GDBSTUB_LOG("[ERROR] Failed to accept connection: %s", e.msg.ptr);
                return false;
            }
        }
        
        // The following methods are identical to tcp_transport thanks to std.socket's abstractions.
        bool connected() const { return conn_sock_ !is null && conn_sock_.isAlive; }

        ptrdiff_t read(void* buf, size_t len) {
            try {
                auto slice = (cast(ubyte*)buf)[0 .. len];
                auto received = conn_sock_.receive(slice);
                if (received == Socket.ERROR) {
                    return -1; // Indicate a real error/disconnect
                }
                return received;
            } catch (SocketException e) {
                return -1;
            }
        }

        ptrdiff_t write(const(void)* buf, size_t len) {
            try {
                size_t total = 0;
                auto slice = (cast(const(ubyte)*)buf)[0 .. len];
                while (total < len) {
                    ptrdiff_t n = conn_sock_.send(slice[total .. $]);
                    if (n == Socket.ERROR) {
                        return total > 0 ? total : -1;
                    }
                    if (n == 0) break; // Connection closed
                    total += n;
                }
                return total;
            } catch (SocketException e) {
                return -1;
            }
        }

        bool readable(int timeout_ms = 0) {
            if (!connected()) return false;
            try {
                auto readSet = new SocketSet();
                readSet.add(conn_sock_);
                
                if (timeout_ms < 0) {
                    // Blocking mode - wait indefinitely
                    return Socket.select(readSet, null, null) > 0;
                } else if (timeout_ms == 0) {
                    // Non-blocking mode
                    return Socket.select(readSet, null, null, dur!"msecs"(0)) > 0;
                } else {
                    // Timed wait
                    return Socket.select(readSet, null, null, dur!"msecs"(timeout_ms)) > 0;
                }
            } catch (SocketException e) {
                return false;
            }
        }

        void disconnect() {
            if (conn_sock_) conn_sock_.close();
        }

        void close() {
            disconnect();
            if (listen_sock_) listen_sock_.close();
            if (path_.length > 0) {
                import core.sys.posix.unistd : unlink;
                unlink(path_.ptr);
                path_ = null;
            }
        }
    }
}

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
class server(Target, Transport = tcp_transport) {
    // Verify that the Target class implements the required interface.
    static assert(__traits(compiles, {
        Target t;
        Nullable!stop_reason r1 = t.cont();
        Nullable!stop_reason r2 = t.stepi();
        size_t sz = t.reg_size(0);
        ubyte[] buf;
        int ret1 = t.read_reg(0, buf);
        const(ubyte)[] cbuf;
        int ret2 = t.write_reg(0, cbuf);
        int ret3 = t.read_mem(0, 0, buf);
        int ret4 = t.write_mem(0, 0, cbuf);
    }), "Target must implement required gdbstub interface methods");
private:
    Target* target_; // Use pointer to support both struct and class targets
    arch_info arch_;
    Transport transport_;

    // Packet handling
    packet_buffer rx_buffer_;
    packet_buffer tx_buffer_;

    // Reusable buffers for efficiency
    ubyte[] reg_buffer_;
    char[] hex_buffer_;

    // Interrupt handling
    shared bool async_io_enabled_;

    // Protocol state
    bool no_ack_mode_ = false;

    // Protocol constants
    enum immutable(char)[] ack = "+";
    enum immutable(char)[] nack = "-";
    enum immutable(char) interrupt_char = '\x03';

public:
    // Integration pattern 3: Callbacks
    void delegate() on_break;    ///< Called when target breaks.
    void delegate() on_continue; ///< Called when target continues.
    void delegate() on_detach;   ///< Called when debugger detaches.

    /**
     * @brief Construct server with a target and its architecture info.
     */
    this(ref Target target, arch_info arch) {
        this.target_ = &target;
        enforce(target_ !is null, "Target cannot be null");
        this.arch_ = arch;
        enforce(arch_.reg_count > 0, "invalid register count");
        // Default cpu_count to 1 if not specified.
        if (arch_.cpu_count <= 0) {
            arch_.cpu_count = 1;
        }

        this.transport_ = new Transport();
        this.rx_buffer_ = new packet_buffer();
        this.tx_buffer_ = new packet_buffer();
    }

    ~this() { stop(); }

    /**
     * @brief Start listening on the specified address.
     * @param address Format: "host:port" for TCP, or a path for a Unix socket.
     */
    bool listen(string address) { return transport_.listen(address); }

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
            if (action == gdb_action.shutdown) {
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
            if (rx_buffer_.needs_ack() && !no_ack_mode_) {
                send_ack();
                rx_buffer_.mark_ack_sent();
            }

            auto action = process_current_packet();

            if (action == gdb_action.shutdown) {
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
    ptrdiff_t read_and_process_data(int timeout_ms) {
        if (!transport_.readable(timeout_ms)) {
            return 0; // Timed out, no data
        }

        char[1024] temp;
        ptrdiff_t n = transport_.read(temp.ptr, temp.length);

        if (n <= 0) {
            if (n < 0) { // Indicates a real error
                GDBSTUB_LOG("[SERVER] Connection closed by peer.");
                transport_.disconnect();
            }
            return n;
        }

        // Scan for interrupt if we are in a 'continue' state.
        if (async_io_enabled_.atomicLoad()) {
            char* data_start = temp.ptr;
            char* data_end = temp.ptr + n;

            // Handle multiple interrupts and packet data mixed together
            while (true) {
                auto interrupt_pos_slice = find(data_start[0 .. data_end - data_start], interrupt_char);
                auto interrupt_pos = interrupt_pos_slice.ptr;

                // Append data before the interrupt (or all data if no interrupt)
                if (interrupt_pos > data_start) {
                    rx_buffer_.append(data_start[0 .. interrupt_pos - data_start]);
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
            rx_buffer_.append(temp[0 .. n]);
        }

        return n;
    }

    /**
     * @brief Handle an interrupt signal (^C) from the debugger.
     */
    void handle_interrupt() {
        GDBSTUB_LOG("[SERVER] Interrupt (Ctrl+C) received from debugger.");
        static if (has_interrupt!Target) {
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
            if (read_and_process_data(-1) < 0) {
                // Disconnected or error
                GDBSTUB_LOG("[SERVER] Connection lost while waiting for packet.");
                return false;
            }
        }

        // Per protocol, ACK/NAK is the first response.
        if (rx_buffer_.needs_ack() && !no_ack_mode_) {
            send_ack();
            rx_buffer_.mark_ack_sent();
        }

        return true;
    }

    /**
     * @brief Send an acknowledgment ('+').
     */
    void send_ack() { transport_.write(ack.ptr, 1); }

    /**
     * @brief Send a packet with a calculated checksum.
     */
    void send_packet(string data) {
        auto packet = tx_buffer_.build_packet(data);
        GDBSTUB_LOG("TX> %.*s", cast(int) packet.length, packet.ptr);
        transport_.write(packet.ptr, packet.length);
    }

    /**
     * @brief Send an error response (e.g., "E22").
     */
    void send_error(gdb_errno error_code) {
        string buf = format("E%02x", cast(int) error_code);
        GDBSTUB_LOG("[ERROR] Sending error response: %s", buf.ptr);
        send_packet(buf);
    }

    /**
     * @brief Process the current packet in the receive buffer.
     */
    gdb_action process_current_packet() {
        auto packet = rx_buffer_.get_packet();
        GDBSTUB_LOG("RX< %.*s", cast(int) packet.length, packet.ptr);

        // Verify checksum before processing.
        if (!rx_buffer_.verify_checksum()) {
            GDBSTUB_LOG(
                "[ERROR] Checksum failed for packet: %.*s", cast(int) packet.length,
                packet.ptr
            );
            if (!no_ack_mode_) {
                transport_.write(nack.ptr, 1);
            }
            rx_buffer_.consume_packet();
            return gdb_action.none;
        }

        gdb_action action = gdb_action.none;

        auto payload = rx_buffer_.get_payload();
        if (payload.length > 0) {
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
    void ensure_buffer_size(ref ubyte[] buffer, size_t size) {
        if (buffer.length < size) {
            buffer.length = size * 2;
        }
    }

    void ensure_buffer_size(ref char[] buffer, size_t size) {
        if (buffer.length < size) {
            buffer.length = size * 2;
        }
    }

    /**
     * @brief Dispatch a command based on the first character of the packet payload.
     */
    gdb_action dispatch_command(string payload) {
        char cmd = payload[0];
        auto args = payload[1 .. $];

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
        case 'C': // Continue with signal (signal ignored)
            return handle_continue(args);
        case 's':
        case 'S': // Step with signal (signal ignored)
            return handle_step(args);

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
            return gdb_action.none;
        }
    }

    // --- Command Handlers ---

    /**
     * @brief Helper to perform a resume action and wait for a stop reason.
     */
    gdb_action resume_and_wait(Nullable!stop_reason delegate() resume_fn) {
        async_io_enabled_.atomicStore(true);
        if (on_continue) {
            on_continue();
        }

        auto reason = resume_fn();

        async_io_enabled_.atomicStore(false);
        if (!reason.isNull) {
            send_stop_reply(reason.get);
            if (on_break) {
                on_break();
            }
            return gdb_action.stop;
        }
        // if we are here, target is still running, so no action for the stub
        return gdb_action.none;
    }

    gdb_action handle_read_all_registers() {
        GDBSTUB_LOG("[CMD g] Reading all registers (%d regs)", arch_.reg_count);
        size_t total_hex_size = 0;
        for (int i = 0; i < arch_.reg_count; ++i) {
            size_t reg_size = target_.reg_size(i);
            if (reg_size > MAX_REG_SIZE) {
                send_error(gdb_errno.gdb_EINVAL);
                return gdb_action.none;
            }
            total_hex_size += reg_size * 2;
        }

        if (total_hex_size > MAX_PACKET_SIZE) {
            send_error(gdb_errno.gdb_ENOSPC); // Too large for packet
            return gdb_action.none;
        }

        ensure_buffer_size(hex_buffer_, total_hex_size + 1);
        char* hex_ptr = hex_buffer_.ptr;

        for (int i = 0; i < arch_.reg_count; ++i) {
            size_t reg_size = target_.reg_size(i);
            if (reg_size == 0) {
                continue;
            }

            ensure_buffer_size(reg_buffer_, reg_size);

            if (target_.read_reg(i, reg_buffer_[0 .. reg_size]) != 0) {
                // Per GDB docs, 'xx' indicates an unavailable register.
                memset(hex_ptr, 'x', reg_size * 2);
            } else {
                if (arch_.swap_registers_endianness) {
                    swap_bytes(reg_buffer_.ptr, reg_size);
                }
                bytes_to_hex(reg_buffer_.ptr, reg_size, hex_ptr);
            }
            hex_ptr += reg_size * 2;
        }

        send_packet(cast(string) hex_buffer_[0 .. total_hex_size]);
        return gdb_action.none;
    }

    gdb_action handle_write_all_registers(string args) {
        GDBSTUB_LOG("[CMD G] Writing all registers (%d regs)", arch_.reg_count);
        size_t pos = 0;
        for (int i = 0; i < arch_.reg_count; ++i) {
            size_t reg_size = target_.reg_size(i);
            if (reg_size == 0) {
                continue;
            }

            if (pos + reg_size * 2 > args.length) {
                send_error(gdb_errno.gdb_EINVAL);
                return gdb_action.none;
            }

            ensure_buffer_size(reg_buffer_, reg_size);
            if (!hex_to_bytes(args.ptr + pos, reg_size * 2, reg_buffer_.ptr)) {
                send_error(gdb_errno.gdb_EINVAL);
                return gdb_action.none;
            }

            if (arch_.swap_registers_endianness) {
                swap_bytes(reg_buffer_.ptr, reg_size);
            }

            if (target_.write_reg(i, reg_buffer_[0 .. reg_size]) != 0) {
                GDBSTUB_LOG("[ERROR] Target write_reg failed for reg %d", i);
                send_error(gdb_errno.gdb_EFAULT);
                return gdb_action.none;
            }
            pos += reg_size * 2;
        }

        send_packet("OK");
        return gdb_action.none;
    }

    gdb_action handle_read_register(string args) {
        int regno;
        try {
            regno = parse!int(args, 16);
        } catch (Exception e) {
            send_error(gdb_errno.gdb_EINVAL);
            return gdb_action.none;
        }

        if (regno < 0 || regno >= arch_.reg_count) {
            send_error(gdb_errno.gdb_EINVAL);
            return gdb_action.none;
        }

        GDBSTUB_LOG("[CMD p] Reading register %d", regno);
        size_t reg_size = target_.reg_size(regno);
        if (reg_size == 0 || reg_size > MAX_REG_SIZE) {
            send_error(gdb_errno.gdb_EINVAL);
            return gdb_action.none;
        }

        ensure_buffer_size(reg_buffer_, reg_size);
        if (target_.read_reg(regno, reg_buffer_[0 .. reg_size]) != 0) {
            send_error(gdb_errno.gdb_EFAULT);
            return gdb_action.none;
        }

        if (arch_.swap_registers_endianness) {
            swap_bytes(reg_buffer_.ptr, reg_size);
        }

        ensure_buffer_size(hex_buffer_, reg_size * 2 + 1);
        bytes_to_hex(reg_buffer_.ptr, reg_size, hex_buffer_.ptr);

        send_packet(cast(string) hex_buffer_[0 .. reg_size * 2]);
        return gdb_action.none;
    }

    gdb_action handle_write_register(string args) {
        import std.string : indexOf;
        auto eq_pos = args.indexOf('=');
        if (eq_pos == -1) {
            send_error(gdb_errno.gdb_EINVAL);
            return gdb_action.none;
        }

        int regno;
        try {
            regno = to!int(args[0 .. eq_pos], 16);
        } catch (Exception e) {
            send_error(gdb_errno.gdb_EINVAL);
            return gdb_action.none;
        }
        if (regno < 0 || regno >= arch_.reg_count) {
            send_error(gdb_errno.gdb_EINVAL);
            return gdb_action.none;
        }

        auto hex_data = args[eq_pos + 1 .. $];
        size_t reg_size = target_.reg_size(regno);
        if (reg_size == 0 || hex_data.length != reg_size * 2) {
            send_error(gdb_errno.gdb_EINVAL);
            return gdb_action.none;
        }

        GDBSTUB_LOG("[CMD P] Writing register %d (size %s)", regno, reg_size);
        ensure_buffer_size(reg_buffer_, reg_size);
        if (!hex_to_bytes(hex_data.ptr, hex_data.length, reg_buffer_.ptr)) {
            send_error(gdb_errno.gdb_EINVAL);
            return gdb_action.none;
        }

        if (arch_.swap_registers_endianness) {
            swap_bytes(reg_buffer_.ptr, reg_size);
        }

        if (target_.write_reg(regno, reg_buffer_[0 .. reg_size]) != 0) {
            GDBSTUB_LOG("[ERROR] Target write_reg failed for reg %d", regno);
            send_error(gdb_errno.gdb_EFAULT);
            return gdb_action.none;
        }

        send_packet("OK");
        return gdb_action.none;
    }

    gdb_action handle_read_memory(string args) {
        auto comma_pos = args.indexOf(',');
        if (comma_pos == -1) {
            send_error(gdb_errno.gdb_EINVAL);
            return gdb_action.none;
        }

        size_t addr, len;
        try {
            addr = to!size_t(args[0 .. comma_pos], 16);
            len = to!size_t(args[comma_pos + 1 .. $], 16);
        } catch (Exception e) {
            send_error(gdb_errno.gdb_EINVAL);
            return gdb_action.none;
        }

        len = min(len, MAX_MEMORY_READ);
        GDBSTUB_LOG("[CMD m] Reading memory at 0x%x, length %s", addr, len);
        ubyte[] data = new ubyte[len];

        if (target_.read_mem(addr, len, data) != 0) {
            send_error(gdb_errno.gdb_EFAULT);
            return gdb_action.none;
        }

        ensure_buffer_size(hex_buffer_, len * 2 + 1);
        bytes_to_hex(data.ptr, len, hex_buffer_.ptr);

        send_packet(cast(string) hex_buffer_[0 .. len * 2]);
        return gdb_action.none;
    }

    gdb_action handle_write_memory(string args) {
        auto colon_pos = args.indexOf(':');
        if (colon_pos == -1) {
            send_error(gdb_errno.gdb_EINVAL);
            return gdb_action.none;
        }

        auto comma_pos = args[0 .. colon_pos].indexOf(',');
        if (comma_pos == -1) {
            send_error(gdb_errno.gdb_EINVAL);
            return gdb_action.none;
        }

        size_t addr, len;
        try {
            addr = to!size_t(args[0 .. comma_pos], 16);
            len = to!size_t(args[comma_pos + 1 .. colon_pos], 16);
        } catch (Exception e) {
            send_error(gdb_errno.gdb_EINVAL);
            return gdb_action.none;
        }

        GDBSTUB_LOG("[CMD M] Writing memory at 0x%x, length %s", addr, len);
        auto hex_data = args[colon_pos + 1 .. $];
        if (hex_data.length != len * 2) {
            send_error(gdb_errno.gdb_EINVAL);
            return gdb_action.none;
        }

        ubyte[] data = new ubyte[len];
        if (!hex_to_bytes(hex_data.ptr, hex_data.length, data.ptr)) {
            send_error(gdb_errno.gdb_EINVAL);
            return gdb_action.none;
        }

        if (target_.write_mem(addr, len, data) != 0) {
            send_error(gdb_errno.gdb_EFAULT);
            return gdb_action.none;
        }

        send_packet("OK");
        return gdb_action.none;
    }

    gdb_action handle_write_binary_memory(string args) {
        auto colon_pos = args.indexOf(':');
        if (colon_pos == -1) {
            send_error(gdb_errno.gdb_EINVAL);
            return gdb_action.none;
        }

        auto comma_pos = args[0 .. colon_pos].indexOf(',');
        if (comma_pos == -1) {
            send_error(gdb_errno.gdb_EINVAL);
            return gdb_action.none;
        }

        size_t addr, len;
        try {
            addr = to!size_t(args[0 .. comma_pos], 16);
            len = to!size_t(args[comma_pos + 1 .. colon_pos], 16);
        } catch (Exception e) {
            send_error(gdb_errno.gdb_EINVAL);
            return gdb_action.none;
        }

        GDBSTUB_LOG("[CMD X] Writing binary memory at 0x%x, length %s", addr, len);
        char[] data = (cast(char[]) args[colon_pos + 1 .. $]).dup;
        size_t actual_len = unescape_binary(data);

        if (actual_len != len) {
            send_error(gdb_errno.gdb_EINVAL);
            return gdb_action.none;
        }

        if (target_.write_mem(addr, len, cast(const(ubyte)[]) data[0 .. len]) != 0) {
            send_error(gdb_errno.gdb_EFAULT);
            return gdb_action.none;
        }

        send_packet("OK");
        return gdb_action.none;
    }

    gdb_action handle_continue(string args) {
        GDBSTUB_LOG("[CMD c] Continue execution (address arg ignored)");
        return resume_and_wait(&target_.cont);
    }

    gdb_action handle_step(string args) {
        GDBSTUB_LOG("[CMD s] Step one instruction (address arg ignored)");
        return resume_and_wait(&target_.stepi);
    }

    // This function is now corrected to fix compilation errors.
    Nullable!(Tuple!(int, size_t, size_t)) parse_breakpoint_packet(string args)
    {
        auto first_comma = args.indexOf(',');
        if (first_comma == -1) return typeof(return).init;
        auto second_comma = args.indexOf(',', first_comma + 1);
        if (second_comma == -1) return typeof(return).init;

        try {
            int type = to!int(args[0 .. first_comma]);
            size_t addr = to!size_t(args[first_comma + 1 .. second_comma], 16);
            size_t kind = to!size_t(args[second_comma + 1 .. $], 16);
            return nullable(tuple(type, addr, kind));
        } catch (Exception e) {
            return typeof(return).init;
        }
    }

    gdb_action handle_insert_breakpoint(string args) {
        static if (has_breakpoints!Target) {
            auto bp = parse_breakpoint_packet(args);
            if (bp.isNull) {
                send_error(gdb_errno.gdb_EINVAL);
                return gdb_action.none;
            }
            auto type = bp.get[0];
            auto addr = bp.get[1];
            // auto kind = bp.get.kind; // kind is unused for now but part of the protocol
            GDBSTUB_LOG("[CMD Z] Insert breakpoint type %d at 0x%x", type, addr);
            bool ok = target_.set_breakpoint(addr, cast(breakpoint_type) type);
            GDBSTUB_LOG("[CMD Z] Result: %s", ok ? "OK" : "Error");
            send_packet(ok ? "OK" : ""); // Empty string for not supported, OK for success
        } else {
            GDBSTUB_LOG("[CMD Z] Not supported by target");
            send_packet("");
        }
        return gdb_action.none;
    }

    gdb_action handle_remove_breakpoint(string args) {
        static if (has_breakpoints!Target) {
            auto bp = parse_breakpoint_packet(args);
            if (bp.isNull) {
                send_error(gdb_errno.gdb_EINVAL);
                return gdb_action.none;
            }
            auto type = bp.get[0];
            auto addr = bp.get[1];
            // auto kind = bp.get.kind; // kind is unused for now but part of the protocol
            GDBSTUB_LOG("[CMD z] Remove breakpoint type %d at 0x%x", type, addr);
            bool ok = target_.del_breakpoint(addr, cast(breakpoint_type) type);
            GDBSTUB_LOG("[CMD z] Result: %s", ok ? "OK" : "Error");
            send_packet(ok ? "OK" : "");
        } else {
            GDBSTUB_LOG("[CMD z] Not supported by target");
            send_packet("");
        }
        return gdb_action.none;
    }

    gdb_action handle_query(string args) {
        auto colon_pos = args.indexOf(':');
        auto query_name = colon_pos != -1 ? args[0 .. colon_pos] : args;

        GDBSTUB_LOG("[CMD q] Query: '%.*s'", cast(int) query_name.length, query_name.ptr);

        if (query_name == "Supported") {
            auto features = appender!string;
            features.put(format("PacketSize=%x;vContSupported+", MAX_PACKET_SIZE));

            if (arch_.target_desc.length > 0 && arch_.xml_architecture_name.length > 0) {
                features.put(";qXfer:features:read+;xmlRegisters=");
                features.put(arch_.xml_architecture_name);
            }
            static if (has_breakpoints!Target) {
                features.put(";swbreak+;hwbreak+");
            }
            static if (has_host_info!Target) {
                features.put(";qHostInfo+");
            }
            static if (has_register_info!Target) {
                features.put(";qRegisterInfo+");
            }
            static if (has_process_info!Target) {
                features.put(";qProcessInfo+");
            }
            if (!find(args, "QStartNoAckMode+").empty) {
                features.put(";QStartNoAckMode+");
            }
            send_packet(features.data);
        } else if (query_name == "Attached") {
            send_packet("1"); // We are always attached to an existing process.
        } else if (query_name == "C") {
            int current_cpu = 0;
            static if (has_cpu_ops!Target) {
                current_cpu = (cast(const(Target)) *target_).get_cpu();
            }
            // protocol uses 1-based thread IDs.
            send_packet(format("QC%x", current_cpu + 1));
        } else if (query_name == "fThreadInfo") {
            auto response = appender!string;
            response.put("m");
            for (int i = 0; i < arch_.cpu_count; ++i) {
                if (i > 0) {
                    response.put(',');
                }
                response.put(format("%x", i + 1)); // 1-based thread IDs
            }
            send_packet(response.data);
        } else if (query_name == "sThreadInfo") {
            send_packet("l"); // 'l' for last/end of list.
        } else if (query_name == "Symbol") {
            send_packet("OK");
        } else if (query_name == "Xfer") {
            handle_xfer(colon_pos != -1 ? args[colon_pos + 1 .. $] : "");
        } else if (query_name == "HostInfo") {
            handle_host_info();
        } else if (query_name == "MemoryRegionInfo") {
            handle_memory_region_info(colon_pos != -1 ? args[colon_pos + 1 .. $] : "");
        } else if (query_name.startsWith("RegisterInfo")) {
            handle_register_info(query_name[12 .. $]); // Skip "RegisterInfo"
        } else if (query_name == "ProcessInfo") {
            handle_process_info();
        } else {
            GDBSTUB_LOG("[CMD q] Unsupported query: '%.*s'", cast(int) query_name.length, query_name.ptr);
            send_packet("");
        }

        return gdb_action.none;
    }

    gdb_action handle_set_query(string args) {
        GDBSTUB_LOG("[CMD Q] Set: '%.*s'", cast(int) args.length, args.ptr);
        if (args == "StartNoAckMode") {
            no_ack_mode_ = true;
            GDBSTUB_LOG("[SERVER] No-ACK mode enabled.");
            send_packet("OK");
        } else {
            send_packet("");
        }
        return gdb_action.none;
    }

    void handle_xfer(string args) {
        if (!args.startsWith("features:read:target.xml:")) {
            send_packet("");
            return;
        }
        if (arch_.target_desc is null) {
            send_packet("E01");
            return;
        }

        auto offset_str = args[25 .. $];
        auto comma_pos = offset_str.indexOf(',');
        if (comma_pos == -1) {
            send_packet("E01");
            return;
        }

        size_t offset, length;
        try {
            offset = to!size_t(offset_str[0 .. comma_pos], 16);
            length = to!size_t(offset_str[comma_pos + 1 .. $], 16);
        } catch (Exception e) {
            send_packet("E01");
            return;
        }

        GDBSTUB_LOG("[XFER] Read target.xml, offset=%s, len=%s", offset, length);
        string desc = arch_.target_desc;
        if (offset >= desc.length) {
            send_packet("l"); // 'l' indicates end of data.
            return;
        }

        size_t to_send = min(length, desc.length - offset);
        auto response = appender!string;
        response.reserve(to_send + 1);
        response.put((offset + to_send >= desc.length) ? 'l' : 'm');
        response.put(desc[offset .. offset + to_send]);
        send_packet(response.data);
    }

    void handle_host_info() {
        static if (has_host_info!Target) {
            GDBSTUB_LOG("[qHostInfo] Responding with host info.");
            auto info = target_.get_host_info();
            if (info.isNull) {
                send_packet(""); // Target chose not to provide info.
                return;
            }
            auto response = appender!string;
            response.put(format(
                "triple:%s;ptrsize:%d;endian:%s;hostname:%s;",
                info.get.triple, info.get.ptr_size, info.get.endian, info.get.hostname
            ));

            if (info.get.os_version.length > 0) {
                response.put(format("os_version:%s;", info.get.os_version));
            }
            if (info.get.os_build.length > 0) {
                response.put(format("os_build:%s;", info.get.os_build));
            }
            if (info.get.os_kernel.length > 0) {
                response.put(format("os_kernel:%s;", info.get.os_kernel));
            }
            send_packet(response.data);
        } else {
            GDBSTUB_LOG("[qHostInfo] Not supported by target.");
            send_packet("");
        }
    }

    void handle_process_info() {
        static if (has_process_info!Target) {
            GDBSTUB_LOG("[qProcessInfo] Responding with process info.");
            auto info = target_.get_process_info();
            if (info.isNull) {
                send_error(gdb_errno.gdb_EFAULT);
                return;
            }
            send_packet(format(
                "pid:%x;triple:%s;endian:%s;ptrsize:%d;ostype:%s;",
                info.get.pid, info.get.triple, info.get.endian, info.get.ptr_size, info.get.ostype
            ));
        } else {
            GDBSTUB_LOG("[qProcessInfo] Not supported by target.");
            send_packet("");
        }
    }

    void handle_memory_region_info(string addr_str) {
        static if (has_mem_region_info!Target) {
            size_t addr;
            try {
                addr = parse!size_t(addr_str, 16);
            } catch (Exception e) {
                send_error(gdb_errno.gdb_EINVAL);
                return;
            }

            GDBSTUB_LOG("[qMemoryRegionInfo] Query for address 0x%x", addr);
            auto region = target_.get_mem_region_info(addr);
            if (!region.isNull && region.get.size > 0) {
                send_packet(format(
                    "start:%0*zx;size:%0*zx;permissions:%s;", (size_t.sizeof * 2),
                    region.get.start, (size_t.sizeof * 2), region.get.size, region.get.permissions
                ));
            } else {
                send_error(gdb_errno.gdb_EFAULT);
            }
        } else {
            GDBSTUB_LOG("[qMemoryRegionInfo] Not supported by target.");
            send_packet("");
        }
    }

    void handle_register_info(string regno_str) {
        static if (has_register_info!Target) {
            int regno;
            try {
                regno = parse!int(regno_str, 16);
            } catch (Exception e) {
                send_error(gdb_errno.gdb_EINVAL);
                return;
            }

            if (regno < 0 || regno >= arch_.reg_count) {
                // This is not an error, it's how GDB discovers the number of registers
                send_error(gdb_errno.gdb_EINVAL);
                return;
            }
            GDBSTUB_LOG("[qRegisterInfo] Query for register %d", regno);
            auto info = target_.get_register_info(regno);
            if (info.isNull) {
                send_error(gdb_errno.gdb_EFAULT);
                return;
            }

            auto response = appender!string;
            response.put(format(
                "name:%s;bitsize:%d;offset:%d;encoding:%s;format:%s;set:%s;",
                info.get.name, info.get.bitsize, info.get.offset, info.get.encoding, info.get.format, info.get.set
            ));
            if (info.get.alt_name.length > 0) {
                response.put(format("alt-name:%s;", info.get.alt_name));
            }
            if (info.get.dwarf_regnum != -1) {
                response.put(format("dwarf:%d;", info.get.dwarf_regnum));
            }
            if (info.get.generic.length > 0) {
                response.put(format("generic:%s;", info.get.generic));
            }
            send_packet(response.data);
        } else {
            GDBSTUB_LOG("[qRegisterInfo] Not supported by target.");
            send_packet("");
        }
    }

    gdb_action handle_v_packet(string args) {
        // Handle 'vCont?' query packet
        if (args == "Cont?") {
            GDBSTUB_LOG("[CMD v] Packet: 'Cont?'");
            // Advertise support for basic continue and step actions.
            // 't' (stop) and 'r' (range step) are not supported by this simple stub.
            send_packet("vCont;c;C;s;S");
            return gdb_action.none;
        }

        // Handle 'vCont;...' resume packet
        if (args.startsWith("Cont;")) {
            GDBSTUB_LOG("[CMD v] Packet: 'Cont;...'");
            auto actions_str = args["Cont;".length .. $];

            if (actions_str.empty) {
                GDBSTUB_LOG("[vCont] No actions specified in vCont packet.");
                send_error(gdb_errno.gdb_EINVAL);
                return gdb_action.none;
            }

            int current_cpu = 0;
            static if (has_cpu_ops!Target) {
                current_cpu = (cast(const(Target)) *target_).get_cpu();
            }
            const int current_thread_id = current_cpu + 1; // Protocol is 1-based

            char action_to_perform = 0; // 0 means no action decided yet

            // GDB protocol: "For each inferior thread, the leftmost action with a matching thread-id is applied."
            string remainder = actions_str;
            while (remainder.length > 0) {
                auto next_semicolon_pos = remainder.indexOf(';');
                string action_part = next_semicolon_pos != -1 ? remainder[0 .. next_semicolon_pos] : remainder;

                if (action_part.length > 0) {
                    const char action_char = action_part[0];
                    const auto colon_pos = action_part.indexOf(':');

                    bool applies = false;
                    if (colon_pos == -1) {
                        // Default action for all threads that don't have a specific action
                        applies = true;
                    } else {
                        // Action with a thread-id
                        auto thread_id_str = action_part[colon_pos + 1 .. $];
                        long thread_id = 0; // Default to a non-matching ID

                        // The protocol supports "ppid.tid", but this simple stub only handles "tid".
                        // A thread-id can be "-1" for all threads.
                        if (thread_id_str == "-1") {
                            thread_id = -1;
                        } else {
                            // Otherwise, it's a positive hex number
                            try {
                                thread_id = parse!long(thread_id_str, 16);
                            } catch (Exception e) {
                                thread_id = 0; // Invalid, won't match
                            }
                        }

                        if (thread_id == current_thread_id || thread_id == -1) {
                            applies = true;
                        }
                    }

                    if (applies) {
                        action_to_perform = action_char;
                        break; // Found the leftmost action for the current thread.
                    }
                }

                if (next_semicolon_pos == -1) {
                    break;
                }
                remainder = remainder[next_semicolon_pos + 1 .. $];
            }

            // The Target interface doesn't support signals, so C/S are treated as c/s.
            if (action_to_perform == 's' || action_to_perform == 'S') {
                GDBSTUB_LOG("[vCont] Action determined: step");
                return resume_and_wait(&target_.stepi);
            }
            if (action_to_perform == 'c' || action_to_perform == 'C') {
                GDBSTUB_LOG("[vCont] Action determined: continue");
                return resume_and_wait(&target_.cont);
            }

            // Unhandled actions ('t', 'r') or no applicable action for this thread.
            // The GDB spec says other threads remain stopped. For a single-threaded target,
            // this means we do nothing. The safest reply is to report that we are still stopped.
            GDBSTUB_LOG("[vCont] No applicable action. Reporting current status.");
            send_stop_reply(stop_reason(stop_type.signal, gdb_signal.TRAP));
            return gdb_action.stop;
        }

        // Unrecognized 'v' packet
        GDBSTUB_LOG("[CMD v] Unrecognized v-packet: '%.*s'", cast(int) args.length, args.ptr);
        send_packet("");
        return gdb_action.none;
    }

    /**
     * @brief H<op><thread> - set thread for subsequent operations.
     *
     * Note on thread/cpu IDs:
     * The GDB remote protocol uses 1-based, positive integers for thread IDs.
     * Internally, this stub and the Target interface use 0-based CPU IDs.
     * This function is the translation layer between the two.
     */
    gdb_action handle_set_thread(string args) {
        GDBSTUB_LOG("[CMD H] Set thread '%.*s'", cast(int) args.length, args.ptr);
        if (args.length > 1 && (args[0] == 'g' || args[0] == 'c')) {
            static if (has_cpu_ops!Target) {
                auto thread_str = args[1 .. $];
                int thread_id;
                try {
                    thread_id = parse!int(thread_str, 16);
                } catch (Exception e) {
                    send_error(gdb_errno.gdb_EINVAL);
                    return gdb_action.none;
                }

                int cpu_id = 0; // default
                if (thread_id > 0) {
                    cpu_id = thread_id - 1; // protocol is 1-based, we are 0-based
                } else if (thread_id == -1 || thread_id == 0) {
                    cpu_id = 0; // gdb's -1 (all) or 0 (any) are mapped to cpu 0
                }

                if (cpu_id < arch_.cpu_count) {
                    target_.set_cpu(cpu_id);
                } else {
                    send_error(gdb_errno.gdb_EINVAL);
                    return gdb_action.none;
                }
            }
        }
        send_packet("OK");
        return gdb_action.none;
    }

    gdb_action handle_thread_alive(string args) {
        GDBSTUB_LOG("[CMD T] Thread alive? '%.*s'", cast(int) args.length, args.ptr);
        send_packet("OK");
        return gdb_action.none;
    }

    gdb_action handle_halt_reason() {
        GDBSTUB_LOG("[CMD ?] Halt reason requested.");
        send_stop_reply(stop_reason(stop_type.signal, gdb_signal.TRAP));
        return gdb_action.none;
    }

    gdb_action handle_detach() {
        GDBSTUB_LOG("[CMD D] Detach requested. Shutting down.");
        send_packet("OK");
        if (on_detach) {
            on_detach();
        }
        return gdb_action.shutdown;
    }

    gdb_action handle_extended_mode() {
        GDBSTUB_LOG("[CMD !] Extended mode enabled.");
        send_packet("OK");
        return gdb_action.none;
    }

    /**
     * @brief Send a stop reply packet to the debugger.
     *
     * This packet informs the debugger that the target has stopped, and why.
     * It is one of the most important packets for a responsive debugging experience.
     * Format: T<signal_hex_val><key>:<val>;...
     */
    void send_stop_reply(const stop_reason reason) {
        auto reply = appender!string;

        // the signal is always TRAP for breakpoints/watchpoints
        gdb_signal signal_to_send = (reason.type == stop_type.signal) ? reason.signal : gdb_signal.TRAP;
        reply.put(format("T%02x", cast(int) signal_to_send));

        // include watchpoint information if applicable
        string watch_type_str = null;
        switch (reason.type) {
        case stop_type.write_watch:
            watch_type_str = "watch";
            break;
        case stop_type.read_watch:
            watch_type_str = "rwatch";
            break;
        case stop_type.access_watch:
            watch_type_str = "awatch";
            break;
        default:
            // no extra info for signals or simple breakpoints
            break;
        }

        if (watch_type_str !is null) {
            reply.put(format("%s:%0*zx;", watch_type_str, size_t.sizeof * 2, reason.addr));
        }

        // include the current thread
        int current_cpu = 0;
        static if (has_cpu_ops!Target) {
            current_cpu = (cast(const(Target)) *target_).get_cpu();
        }
        reply.put(format("thread:%x;", current_cpu + 1)); // 1-based

        // include the program counter for performance
        if (arch_.pc_reg_num != -1) {
            size_t pc_size = target_.reg_size(arch_.pc_reg_num);
            if (pc_size > 0 && pc_size <= MAX_REG_SIZE) {
                ensure_buffer_size(reg_buffer_, pc_size);
                if (target_.read_reg(arch_.pc_reg_num, reg_buffer_[0 .. pc_size]) == 0) {
                    if (arch_.swap_registers_endianness) {
                        swap_bytes(reg_buffer_.ptr, pc_size);
                    }
                    ensure_buffer_size(hex_buffer_, pc_size * 2 + 1);
                    bytes_to_hex(reg_buffer_.ptr, pc_size, hex_buffer_.ptr);

                    reply.put(format(
                        "%x:%.*s;", arch_.pc_reg_num, cast(int) (pc_size * 2),
                        hex_buffer_.ptr
                    ));
                }
            }
        }

        GDBSTUB_LOG("[EVENT] Target stopped. Sending stop reply: %s", reply.data.ptr);
        send_packet(reply.data);
    }
}

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
void serve(Target)(ref Target target, const arch_info arch, string address) {
    auto stub = new server!Target(target, arch);
    if (!stub.listen(address)) {
        throw new Exception("failed to listen on address");
    }
    stub.serve_forever();
}

/**
 * @brief Create a TCP server instance for more advanced usage patterns.
 * @note In D, this returns a garbage-collected class reference, equivalent
 *       in lifetime management to C++'s std::shared_ptr, not std::unique_ptr.
 */
auto make_tcp_server(Target)(ref Target target, const arch_info arch) {
    return new server!(Target, tcp_transport)(target, arch);
}

version (Posix) {
    /**
     * @brief Create a Unix domain socket server instance for more advanced usage patterns.
     * @note In D, this returns a garbage-collected class reference.
     */
    auto make_unix_server(Target)(ref Target target, const arch_info arch) {
        return new server!(Target, unix_transport)(target, arch);
    }
}