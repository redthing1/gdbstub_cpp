import std.stdio;
import std.conv : to;
import std.string : toStringz;
import gdbstub;
import mock_target;
import core.sys.posix.signal;

MockTarget target;
server!(MockTarget) stub_server = null;

// Signal handler removed for simplicity

void main(string[] args) {
    if (args.length != 2) {
        stderr.writefln("Usage: %s <port>", args[0]);
        return;
    }

    // Signal handling removed for simplicity

    int port = to!int(args[1]);
    string address = "127.0.0.1:" ~ args[1];

    // Output ready signal immediately
    writefln("GDBSTUB_LISTENING_ON_PORT:%d", port);
    stdout.flush();

    try {
        target.reset(); // Initialize the target to a known state
        
        auto arch = arch_info(
            MockTarget.riscv32_target_xml,
            "org.gnu.gdb.riscv.cpu",
            "bare",
            1,  // cpu_count
            33, // reg_count
            32  // pc_reg_num
        );

        stub_server = new server!MockTarget(target, arch);

        if (!stub_server.listen(address)) {
            stderr.writefln("Failed to listen on %s", address);
            return;
        }

        stub_server.serve_forever();

    } catch (Exception e) {
        stderr.writefln("Error: %s", e.msg);
        return;
    }
}