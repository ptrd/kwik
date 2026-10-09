# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & test

Subprojects are renamed in `settings.gradle`, so Gradle project paths differ from directory names:

| Directory | Gradle path / artifact | Java module |
|-----------|------------------------|-------------|
| `core` | `:kwik` | `tech.kwik.core` |
| `cli` | `:kwik-cli` | |
| `h09` | `:kwik-h09` | `tech.kwik.h09` |
| `qlog` | `:kwik-qlog` | `tech.kwik.qlog` |
| `samples` | `:kwik-samples` | `tech.kwik.samples` |
| `interop` | `:kwik-interop` | |

```bash
./gradlew build                                   # build + test all modules (what CI runs, on JDK 17)
./gradlew :kwik:test                              # tests for core only
./gradlew :kwik:test --tests "tech.kwik.core.stream.StreamManagerTest"
./gradlew :kwik:test --tests "tech.kwik.core.stream.StreamManagerTest.methodName"
./gradlew :kwik-cli:assembleDist                  # CLI zip in cli/build/distributions; run via ./kwik.sh
```

- Source/target compatibility is Java 11; shared build config lives in `buildSrc/src/main/groovy/buildlogic.java-common-conventions.gradle`.
- Tests use JUnit 5, Mockito (loaded as `-javaagent`) and AssertJ. Assertions (`assert`) are enabled during tests.
- The project version comes from `git describe`, and `core` writes it to a generated `version.properties`.
- Core's test classes (e.g. `MockPacket`, `TestUtils`) are published as a `testArtifacts` configuration for reuse by other modules.
- TLS 1.3 is provided by the external `tech.kwik:agent15` library (version in `agent15_version`), not by code in this repo.
- Never commit `gradle.properties`: it holds signing and Maven Central credentials.

## Architecture (core, `tech.kwik.core`)

- **Public API** is in the root package plus `server`, `log`, `concurrent` and `generic` (see `module-info.java`). Everything in `impl` packages is internal. Entry points: `QuicClientConnection.newBuilder()` and `ServerConnector.builder()`.
- **Connections**: `impl/QuicConnectionImpl` is the shared base class. The client is `impl/QuicClientConnectionImpl`, the server is `server/impl/ServerConnectionImpl`.
- **Receive path**: a `Receiver` (in `receive/`) reads UDP datagrams. They go through a `DatagramFilter` chain to a role-specific `PacketParser` (`ClientRolePacketParser` / `ServerRolePacketParser`), and each parsed packet then passes a chain of `PacketFilter`s (destination check, duplicate drop, frame checks, qlog, closing/draining) built in `createProcessorChain()` of each connection class. Frames are then dispatched to the connection, which implements `PacketProcessor` / `FrameProcessor`.
- **Server demultiplexing**: `ServerConnectorImpl` owns the socket and routes datagrams by connection ID through `ServerConnectionRegistryImpl`. New connections start as a `ServerConnectionCandidate` (behind `InitialPacketFilterProxy`) until the Initial packet is validated.
- **Send path**: `send/SenderImpl` runs its own sender thread and uses thread confinement for its state. Other code queues `SendRequest`s, and the `GlobalPacketAssembler` builds packets per encryption level, using `ack/` for ACKs and `cc/` + `recovery/` for congestion control and loss detection.
- **Streams**: `stream/StreamManager` creates and limits streams. `QuicStreamImpl` plus its input/output buffers handle flow control.
- **qlog**: core emits events through `QlogPacketFilter`/logger hooks, and the `qlog` module turns them into qlog files. `core.common/frame/packet/util` are exported only to `tech.kwik.qlog`.

## Coding guidelines (from `docs/Coding guidelines.md`; apply to new code, existing code may not follow them)

- **Threading**: received packets and frames of one connection are never processed in parallel, so packet/frame processing methods need no concurrency guards.
- Avoid `synchronized` (virtual threads, and it hides intent). Use a lock with a descriptive name, and call `lock()` before the `try`, not inside it.
- **QUIC version**: pass `version` to larger classes with a lot of behaviour, even if unused, because it is costly to re-introduce. Don't add it to small classes such as frames. Many leftover version variables from the draft era exist.
- **Tests**: use `// region` / `// endregion` markers to group topics in test classes (see `StreamManagerTest`) so duplicate tests are easier to spot.
