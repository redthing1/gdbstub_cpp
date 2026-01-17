module gdbstub_cpp_test;

import gdbstub_cpp;
import core.thread : Thread;
import core.time : dur;
import std.algorithm : canFind, min;
import std.conv : to;
import std.exception : enforce;
import std.format : format;
import std.socket;
import std.string : indexOf, split, startsWith;
import std.typecons : Nullable, nullable;

private enum IntegrationMode {
    blocking,
    polling,
    async,
}

private class TestTarget {
    enum regSizeBytes = 4;
    enum regCount = 8;
    enum memSize = 128;

    private IntegrationMode mode;
    private StopNotifier notifier;
    private bool running;
    private size_t pollTicks;
    private ulong currentThreadId = 1;
    private BreakpointSpec lastBreakpoint;
    private size_t breakpointsSet;
    private size_t breakpointsRemoved;
    private Nullable!RunCapabilities runCaps;
    private Nullable!BreakpointCapabilities breakpointCaps;
    private Nullable!ReplayLogBoundary replayLogOverride;
    private Nullable!ResumeRequest lastResumeRequest;
    private TargetStatus resumeStatus = TargetStatus.ok;

    ubyte[regSizeBytes * regCount] regs;
    ubyte[memSize] mem;
    ulong[] threads = [1, 2];

    this(
        IntegrationMode mode,
        Nullable!RunCapabilities runCaps = Nullable!RunCapabilities.init,
        Nullable!BreakpointCapabilities breakpointCaps = Nullable!BreakpointCapabilities.init,
        Nullable!ReplayLogBoundary replayLogOverride = Nullable!ReplayLogBoundary.init
    ) {
        this.mode = mode;
        this.runCaps = runCaps;
        this.breakpointCaps = breakpointCaps;
        this.replayLogOverride = replayLogOverride;
    }

    Target buildTarget() {
        auto runCapsFn = runCaps.isNull ? null : &getRunCapabilities;
        auto breakCapsFn = breakpointCaps.isNull ? null : &getBreakpointCapabilities;
        auto builder = TargetBuilder()
            .withRegs(&regSize, &readReg, &writeReg)
            .withMem(&readMem, &writeMem)
            .withRun(
                &resume,
                &interrupt,
                mode == IntegrationMode.polling ? &pollStop : null,
                mode == IntegrationMode.async ? &setStopNotifier : null,
                runCapsFn
            )
            .withMemoryLayout(&regionInfo, &memoryMap)
            .withHostInfo(&hostInfo)
            .withProcessInfo(&processInfo)
            .withShlibInfo(&shlibInfo)
            .withBreakpoints(&setBreakpoint, &removeBreakpoint, breakCapsFn)
            .withRegisterInfo(&registerInfo)
            .withThreads(
                &threadIds,
                &currentThread,
                &setCurrentThread,
                &threadPc,
                &threadName,
                &threadStopReason
            );
        return builder.build();
    }

    size_t regSize(int regno) {
        return regSizeBytes;
    }

    TargetStatus readReg(int regno, ubyte[] buffer) {
        auto offset = cast(size_t)(regno * regSizeBytes);
        if (offset + buffer.length > regs.length) {
            return TargetStatus.invalid;
        }
        buffer[] = regs[offset .. offset + buffer.length];
        return TargetStatus.ok;
    }

    TargetStatus writeReg(int regno, const(ubyte)[] data) {
        auto offset = cast(size_t)(regno * regSizeBytes);
        if (offset + data.length > regs.length) {
            return TargetStatus.invalid;
        }
        regs[offset .. offset + data.length] = data[];
        return TargetStatus.ok;
    }

    TargetStatus readMem(ulong addr, ubyte[] buffer) {
        auto start = cast(size_t)addr;
        if (start >= mem.length) {
            return TargetStatus.fault;
        }
        auto count = min(buffer.length, mem.length - start);
        buffer[0 .. count] = mem[start .. start + count];
        return TargetStatus.ok;
    }

    TargetStatus writeMem(ulong addr, const(ubyte)[] data) {
        auto start = cast(size_t)addr;
        if (start >= mem.length) {
            return TargetStatus.fault;
        }
        auto count = min(data.length, mem.length - start);
        mem[start .. start + count] = data[0 .. count];
        return TargetStatus.ok;
    }

    ResumeResult resume(ResumeRequest request) {
        lastResumeRequest = nullable(request);
        running = true;
        pollTicks = 0;
        if (mode == IntegrationMode.blocking) {
            auto result = stoppedResult();
            result.status = resumeStatus;
            return result;
        }
        if (mode == IntegrationMode.async && notifier.isValid()) {
            auto notifyCopy = notifier;
            auto stopReason = stoppedReason();
            auto worker = new Thread(() {
                Thread.sleep(dur!"msecs"(50));
                notifyCopy.notify(stopReason);
            });
            worker.start();
        }
        ResumeResult result;
        result.state = ResumeState.running;
        result.status = resumeStatus;
        return result;
    }

    void interrupt() {
        running = false;
    }

    Nullable!StopReason pollStop() {
        if (!running) {
            return Nullable!StopReason.init;
        }
        pollTicks++;
        if (pollTicks < 2) {
            return Nullable!StopReason.init;
        }
        running = false;
        return nullable(stoppedReason());
    }

    void setStopNotifier(StopNotifier notifier) {
        this.notifier = notifier;
    }

    MemoryRegion[] memoryMap() {
        MemoryRegion region;
        region.start = 0;
        region.size = mem.length;
        region.perms = cast(MemPerm)(MemPerm.read | MemPerm.write);
        region.name = nullable("ram");
        region.types = ["ram"];
        return [region];
    }

    Nullable!MemoryRegionInfo regionInfo(ulong addr) {
        if (addr >= mem.length) {
            return Nullable!MemoryRegionInfo.init;
        }
        MemoryRegionInfo info;
        info.start = 0;
        info.size = mem.length;
        info.mapped = true;
        info.perms = cast(MemPerm)(MemPerm.read | MemPerm.write);
        info.name = nullable("ram");
        info.types = ["ram"];
        return nullable(info);
    }

    Nullable!HostInfo hostInfo() {
        HostInfo info;
        info.triple = "riscv32-unknown-elf";
        info.endian = "little";
        info.ptrSize = 4;
        info.hostname = "d-target";
        return nullable(info);
    }

    Nullable!ProcessInfo processInfo() {
        ProcessInfo info;
        info.pid = 1234;
        info.triple = "riscv32-unknown-elf";
        info.endian = "little";
        info.ptrSize = 4;
        info.ostype = "bare";
        return nullable(info);
    }

    Nullable!ShlibInfo shlibInfo() {
        ShlibInfo info;
        info.infoAddr = nullable(0x11223344UL);
        return nullable(info);
    }

    Nullable!RegisterInfo registerInfo(int regno) {
        if (regno < 0 || regno >= regCount) {
            return Nullable!RegisterInfo.init;
        }

        RegisterInfo info;
        info.name = "r" ~ to!string(regno);
        info.bitsize = regSizeBytes * 8;
        info.offset = nullable(cast(size_t)(regno * regSizeBytes));
        info.encoding = "uint";
        info.format = "hex";

        if (regno == 0) {
            info.altName = nullable("zero");
            info.set = nullable("general");
            info.gccRegnum = nullable(0);
            info.dwarfRegnum = nullable(0);
            info.generic = nullable("arg1");
            info.containerRegs = [1, 2];
            info.invalidateRegs = [3];
        }

        return nullable(info);
    }

    TargetStatus setBreakpoint(BreakpointSpec spec) {
        lastBreakpoint = spec;
        breakpointsSet++;
        return TargetStatus.ok;
    }

    TargetStatus removeBreakpoint(BreakpointSpec spec) {
        lastBreakpoint = spec;
        breakpointsRemoved++;
        return TargetStatus.ok;
    }

    Nullable!RunCapabilities getRunCapabilities() {
        return runCaps;
    }

    Nullable!BreakpointCapabilities getBreakpointCapabilities() {
        return breakpointCaps;
    }

    size_t breakpointsSetCount() {
        return breakpointsSet;
    }

    size_t breakpointsRemovedCount() {
        return breakpointsRemoved;
    }

    Nullable!ResumeRequest lastResumeRequestValue() {
        return lastResumeRequest;
    }

    void setResumeStatus(TargetStatus status) {
        resumeStatus = status;
    }

    ulong currentThreadValue() {
        return currentThreadId;
    }

    ulong[] threadIds() {
        return threads;
    }

    ulong currentThread() {
        return currentThreadId;
    }

    TargetStatus setCurrentThread(ulong tid) {
        currentThreadId = tid;
        return TargetStatus.ok;
    }

    Nullable!ulong threadPc(ulong tid) {
        return nullable(0x1000 + tid);
    }

    Nullable!string threadName(ulong tid) {
        return nullable("thread-" ~ to!string(tid));
    }

    Nullable!StopReason threadStopReason(ulong tid) {
        auto reason = stoppedReason();
        reason.threadId = nullable(tid);
        return nullable(reason);
    }

    private StopReason stoppedReason() {
        StopReason reason;
        reason.kind = StopKind.signal;
        reason.signal = 5; // SIGTRAP
        if (!replayLogOverride.isNull) {
            reason.replayLog = replayLogOverride;
        }
        return reason;
    }

    private ResumeResult stoppedResult() {
        ResumeResult result;
        result.state = ResumeState.stopped;
        result.stop = stoppedReason();
        return result;
    }
}

private class ServerHarness {
    Server server;
    Thread thread;
    TestTarget target;
    string address;
    string targetXml;
    string xmlArchName;

    this(
        IntegrationMode mode,
        Nullable!RunCapabilities runCaps = Nullable!RunCapabilities.init,
        Nullable!BreakpointCapabilities breakCaps = Nullable!BreakpointCapabilities.init,
        Nullable!ReplayLogBoundary replayLog = Nullable!ReplayLogBoundary.init
    ) {
        target = new TestTarget(mode, runCaps, breakCaps, replayLog);
        auto targetHandle = target.buildTarget();

        ArchSpec arch;
        targetXml = "<target version=\"1.0\"><architecture>riscv:rv32</architecture></target>";
        xmlArchName = "riscv";
        arch.targetXml = targetXml;
        arch.xmlArchName = xmlArchName;
        arch.regCount = TestTarget.regCount;
        arch.pcRegNum = TestTarget.regCount - 1;
        arch.osabi = "bare";

        auto transport = new TransportTcp();
        auto port = pickFreePort();
        address = "127.0.0.1:" ~ to!string(port);
        server = new Server(targetHandle, arch, transport);
        enforce(server.listen(address), "listen failed");

        thread = new Thread({
            if (!server.waitForConnection()) {
                return;
            }
            while (server.hasConnection()) {
                server.poll(5);
                Thread.sleep(dur!"msecs"(1));
            }
        });
        thread.start();
    }

    void stop() {
        server.stop();
        if (thread.isRunning()) {
            thread.join();
        }
    }
}

private ushort pickFreePort() {
    auto socket = new TcpSocket(AddressFamily.INET);
    socket.bind(new InternetAddress("127.0.0.1", 0));
    auto address = cast(InternetAddress)socket.localAddress();
    auto port = address.port();
    socket.close();
    return port;
}

private class RspClient {
    TcpSocket socket;

    this(string address) {
        auto parts = address.split(":");
        enforce(parts.length == 2, "invalid address");
        auto host = parts[0];
        auto port = to!ushort(parts[1]);
        socket = new TcpSocket(AddressFamily.INET);
        socket.connect(new InternetAddress(host, port));
    }

    void close() {
        socket.close();
    }

    void sendPacket(string payload) {
        auto packet = "$" ~ payload ~ "#" ~ checksum(payload);
        socket.send(packet);
    }

    string readPacket() {
        ubyte ch;
        do {
            ch = readByte();
        } while (ch != '$');

        string payload;
        while (true) {
            ch = readByte();
            if (ch == '#') {
                break;
            }
            payload ~= cast(char)ch;
        }

        readByte();
        readByte();
        socket.send("+");
        return payload;
    }

    private string checksum(string payload) {
        uint sum = 0;
        foreach (c; payload) {
            sum = (sum + cast(ubyte)c) & 0xFF;
        }
        return format("%02x", sum);
    }

    private ubyte readByte() {
        ubyte[1] buf;
        auto received = socket.receive(buf);
        enforce(received == 1, "connection closed");
        return buf[0];
    }
}

private string hexU64(ulong value) {
    return format("%x", value);
}

private string hexEncode(const(ubyte)[] data) {
    enum hex = "0123456789abcdef";
    char[] hexOut;
    hexOut.length = data.length * 2;
    foreach (i, b; data) {
        hexOut[i * 2] = hex[(b >> 4) & 0x0f];
        hexOut[i * 2 + 1] = hex[b & 0x0f];
    }
    return hexOut.idup;
}

private string hexEncodeU64Sized(ulong value, size_t size) {
    ubyte[] data;
    data.length = size;
    foreach (i; 0 .. size) {
        auto shift = (size - 1 - i) * 8;
        data[i] = cast(ubyte)((value >> shift) & 0xff);
    }
    return hexEncode(data);
}

private ubyte hexValue(char c) {
    if (c >= '0' && c <= '9') {
        return cast(ubyte)(c - '0');
    }
    if (c >= 'a' && c <= 'f') {
        return cast(ubyte)(10 + c - 'a');
    }
    if (c >= 'A' && c <= 'F') {
        return cast(ubyte)(10 + c - 'A');
    }
    enforce(false, "invalid hex digit");
    return 0;
}

private string decodeHexString(string hex) {
    enforce(hex.length % 2 == 0, "hex length must be even");
    ubyte[] decoded;
    decoded.length = hex.length / 2;
    foreach (i; 0 .. decoded.length) {
        auto hi = hexValue(hex[i * 2]);
        auto lo = hexValue(hex[i * 2 + 1]);
        decoded[i] = cast(ubyte)((hi << 4) | lo);
    }
    return cast(string)decoded;
}

private string[string] parseKeyValues(string payload) {
    string[string] map;
    foreach (part; payload.split(";")) {
        if (part.length == 0) {
            continue;
        }
        auto colon = part.indexOf(":");
        if (colon < 0) {
            continue;
        }
        map[part[0 .. colon]] = part[colon + 1 .. $];
    }
    return map;
}

private string escapeBinary(const(ubyte)[] data) {
    char[] escaped;
    escaped.reserve(data.length);
    foreach (b; data) {
        char c = cast(char)b;
        if (c == '$' || c == '#' || c == '}') {
            escaped ~= '}';
            escaped ~= cast(char)(c ^ 0x20);
        } else {
            escaped ~= c;
        }
    }
    return escaped.idup;
}

private ubyte[] unescapeBinary(string data) {
    auto buf = data.dup;
    size_t write = 0;
    for (size_t i = 0; i < buf.length; ++i) {
        char c = buf[i];
        if (c == '}' && i + 1 < buf.length) {
            buf[write++] = cast(char)(buf[i + 1] ^ 0x20);
            ++i;
        } else {
            buf[write++] = c;
        }
    }
    return cast(ubyte[])buf[0 .. write];
}

private void runBasicProtocolChecks(IntegrationMode mode) {
    auto harness = new ServerHarness(mode);
    scope(exit) harness.stop();

    auto client = new RspClient(harness.address);
    scope(exit) client.close();

    client.sendPacket("qSupported");
    auto supported = client.readPacket();
    assert(supported.canFind("PacketSize="));
    assert(supported.canFind("vContSupported+"));
    assert(supported.canFind("QStartNoAckMode+"));
    assert(supported.canFind("qXfer:features:read+"));
    assert(supported.canFind("xmlRegisters=" ~ harness.xmlArchName));
    assert(supported.canFind("swbreak+"));
    assert(supported.canFind("qHostInfo+"));
    assert(supported.canFind("qProcessInfo+"));
    assert(supported.canFind("qMemoryRegionInfo+"));
    assert(supported.canFind("qXfer:memory-map:read+"));

    client.sendPacket("qGDBServerVersion");
    auto versionFields = parseKeyValues(client.readPacket());
    assert(versionFields["name"] == "gdbstub_cpp");
    assert(versionFields["version"].length > 0);

    client.sendPacket("qAttached");
    assert(client.readPacket() == "1");

    client.sendPacket("qSymbol::");
    assert(client.readPacket() == "OK");

    client.sendPacket("vCont?");
    assert(client.readPacket() == "vCont;c;C;s;S");

    client.sendPacket("QStartNoAckMode");
    assert(client.readPacket() == "OK");

    auto firstLen = 8UL;
    client.sendPacket("qXfer:features:read:target.xml:0," ~ hexU64(firstLen));
    auto part1 = client.readPacket();
    assert(part1.length > 1);
    assert(part1[0] == 'm');
    auto xmlCombined = part1[1 .. $];

    client.sendPacket("qXfer:features:read:target.xml:" ~ hexU64(firstLen) ~ "," ~ hexU64(0x1000));
    auto part2 = client.readPacket();
    assert(part2.length > 1);
    assert(part2[0] == 'l');
    xmlCombined ~= part2[1 .. $];
    assert(xmlCombined == harness.targetXml);

    client.sendPacket("qXfer:memory-map:read::0,fff");
    auto memMap = client.readPacket();
    assert(memMap.length > 1);
    assert(memMap[0] == 'l');
    auto memXml = memMap[1 .. $];
    assert(memXml.canFind("<memory-map>"));
    assert(memXml.canFind("start=\"0x0\""));
    assert(memXml.canFind("length=\"0x" ~ hexU64(TestTarget.memSize) ~ "\""));

    client.sendPacket("g");
    auto regs = client.readPacket();
    assert(regs.length == TestTarget.regCount * TestTarget.regSizeBytes * 2);

    client.sendPacket("P0=01020304");
    assert(client.readPacket() == "OK");

    client.sendPacket("p0");
    assert(client.readPacket() == "01020304");

    client.sendPacket("M0,4:00010203");
    assert(client.readPacket() == "OK");

    client.sendPacket("m0,4");
    assert(client.readPacket() == "00010203");

    auto binData = cast(ubyte[])[0x00, 0x24, 0x23, 0x7d];
    auto binPayload = escapeBinary(binData);
    client.sendPacket("X0,4:" ~ binPayload);
    assert(client.readPacket() == "OK");

    client.sendPacket("x0,4");
    auto binResp = client.readPacket();
    auto binDecoded = unescapeBinary(binResp);
    assert(binDecoded == binData);

    client.sendPacket("qRegisterInfo0");
    auto regInfo = parseKeyValues(client.readPacket());
    assert(regInfo["name"] == "r0");
    assert(regInfo["alt-name"] == "zero");
    assert(regInfo["bitsize"] == to!string(TestTarget.regSizeBytes * 8));
    assert(regInfo["offset"] == "0");
    assert(regInfo["encoding"] == "uint");
    assert(regInfo["format"] == "hex");
    assert(regInfo["set"] == "general");
    assert(regInfo["gcc"] == "0");
    assert(regInfo["dwarf"] == "0");
    assert(regInfo["generic"] == "arg1");
    assert(regInfo["container-regs"] == "1,2");
    assert(regInfo["invalidate-regs"] == "3");

    client.sendPacket("qRegisterInfo7");
    auto regInfo7 = parseKeyValues(client.readPacket());
    assert(regInfo7["name"] == "r7");

    client.sendPacket("qRegisterInfo8");
    assert(client.readPacket() == "E45");

    client.sendPacket("qMemoryRegionInfo:0");
    auto memInfo = client.readPacket();
    assert(memInfo.canFind("start:"));
    assert(memInfo.canFind("size:" ~ hexEncodeU64Sized(TestTarget.memSize, 8)));
    assert(memInfo.canFind("permissions:rw"));

    client.sendPacket("qHostInfo");
    auto hostFields = parseKeyValues(client.readPacket());
    assert(decodeHexString(hostFields["triple"]) == "riscv32-unknown-elf");
    assert(hostFields["endian"] == "little");
    assert(hostFields["ptrsize"] == "4");
    assert(decodeHexString(hostFields["hostname"]) == "d-target");

    client.sendPacket("qProcessInfo");
    auto procFields = parseKeyValues(client.readPacket());
    assert(procFields["pid"] == hexU64(1234));
    assert(decodeHexString(procFields["triple"]) == "riscv32-unknown-elf");
    assert(procFields["endian"] == "little");
    assert(procFields["ptrsize"] == "4");
    assert(procFields["ostype"] == "bare");

    client.sendPacket("qShlibInfoAddr");
    assert(client.readPacket() == hexEncodeU64Sized(0x11223344UL, 4));

    client.sendPacket("qfThreadInfo");
    auto threadList = client.readPacket();
    assert(threadList.startsWith("m"));
    assert(threadList.canFind("1"));
    assert(threadList.canFind("2"));

    client.sendPacket("qsThreadInfo");
    assert(client.readPacket() == "l");

    client.sendPacket("qC");
    assert(client.readPacket() == "QC1");

    client.sendPacket("qThreadStopInfo2");
    auto stopInfo = client.readPacket();
    assert(stopInfo.startsWith("T05"));
    assert(stopInfo.canFind("thread:2"));

    client.sendPacket("jThreadsInfo");
    auto threadsJson = client.readPacket();
    assert(threadsJson.startsWith("["));
    assert(threadsJson.canFind("\"tid\":1"));
    assert(threadsJson.canFind("\"tid\":2"));

    client.sendPacket("jThreadExtendedInfo:{\"thread\":2}");
    auto threadExt = client.readPacket();
    assert(threadExt.startsWith("{"));
    assert(threadExt.canFind("\"thread\":2"));
    assert(threadExt.canFind("\"name\":\"thread-2\""));

    client.sendPacket("QThreadSuffixSupported");
    assert(client.readPacket() == "OK");

    client.sendPacket("p0;thread:2;");
    assert(client.readPacket() == "01020304");
    assert(harness.target.currentThreadValue() == 2);

    client.sendPacket("qC");
    assert(client.readPacket() == "QC2");

    client.sendPacket("Hg1");
    assert(client.readPacket() == "OK");
    assert(harness.target.currentThreadValue() == 1);

    client.sendPacket("T2");
    assert(client.readPacket() == "OK");

    client.sendPacket("Z0,0,4");
    assert(client.readPacket() == "OK");
    assert(harness.target.breakpointsSetCount() == 1);

    client.sendPacket("z0,0,4");
    assert(client.readPacket() == "OK");
    assert(harness.target.breakpointsRemovedCount() == 1);

    client.sendPacket("QListThreadsInStopReply");
    assert(client.readPacket() == "OK");

    client.sendPacket("c");
    auto stop = client.readPacket();
    assert(stop.startsWith("T05") || stop.startsWith("S05"));
    assert(stop.canFind("thread:"));
    assert(stop.canFind("threads:1,2"));
    assert(stop.canFind("thread-pcs:"));
}

private void runCapabilitiesProtocolChecks() {
    RunCapabilities runCaps;
    runCaps.reverseContinue = true;
    runCaps.reverseStep = true;
    runCaps.rangeStep = true;
    runCaps.nonStop = true;

    BreakpointCapabilities breakCaps;
    breakCaps.software = true;
    breakCaps.hardware = true;
    breakCaps.watchRead = true;
    breakCaps.watchWrite = true;
    breakCaps.watchAccess = true;

    auto harness = new ServerHarness(
        IntegrationMode.blocking,
        nullable(runCaps),
        nullable(breakCaps),
        nullable(ReplayLogBoundary.begin)
    );
    scope(exit) harness.stop();

    auto client = new RspClient(harness.address);
    scope(exit) client.close();

    client.sendPacket("qSupported");
    auto supported = client.readPacket();
    assert(supported.canFind("ReverseContinue+"));
    assert(supported.canFind("ReverseStep+"));
    assert(supported.canFind("QNonStop+"));
    assert(supported.canFind("hwbreak+"));

    client.sendPacket("vCont?");
    auto vCont = client.readPacket();
    assert(vCont.canFind(";r"));
    assert(vCont.canFind(";t"));

    client.sendPacket("bc");
    auto reverseContStop = client.readPacket();
    auto lastRequest = harness.target.lastResumeRequestValue();
    assert(!lastRequest.isNull);
    assert(lastRequest.get.action == ResumeAction.cont);
    assert(lastRequest.get.direction == ResumeDirection.reverse);
    assert(reverseContStop.canFind("replaylog:begin"));

    client.sendPacket("bs");
    auto reverseStepStop = client.readPacket();
    lastRequest = harness.target.lastResumeRequestValue();
    assert(!lastRequest.isNull);
    assert(lastRequest.get.action == ResumeAction.step);
    assert(lastRequest.get.direction == ResumeDirection.reverse);

    client.sendPacket("vCont;r10,20");
    auto rangeStop = client.readPacket();
    lastRequest = harness.target.lastResumeRequestValue();
    assert(!lastRequest.isNull);
    assert(lastRequest.get.action == ResumeAction.rangeStep);
    assert(!lastRequest.get.range.isNull);
    assert(lastRequest.get.range.get.start == 0x10);
    assert(lastRequest.get.range.get.end == 0x20);
    assert(rangeStop.startsWith("T05") || rangeStop.startsWith("S05"));
}

private void runResumeStatusChecks() {
    auto harness = new ServerHarness(IntegrationMode.blocking);
    scope(exit) harness.stop();
    harness.target.setResumeStatus(TargetStatus.invalid);

    auto client = new RspClient(harness.address);
    scope(exit) client.close();

    client.sendPacket("c");
    assert(client.readPacket() == "E16");
}

unittest {
    runBasicProtocolChecks(IntegrationMode.blocking);
}

unittest {
    runBasicProtocolChecks(IntegrationMode.polling);
}

unittest {
    runBasicProtocolChecks(IntegrationMode.async);
}

unittest {
    runCapabilitiesProtocolChecks();
}

unittest {
    runResumeStatusChecks();
}
