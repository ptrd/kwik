# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project overview

Kwik is a Java implementation of the QUIC protocol (RFC 9000, RFC 9369/QUICv2), providing both client and
server functionality, plus a TLS 1.3 stack, an HTTP/0.9 add-on, qlog support, a CLI sample client, and an
interop test runner. It's a Gradle multi-module project targeting Java 11 source/target compatibility (built
with Java 17 in CI).

## Build & test commands

Build everything:
```
./gradlew build
```

Run all tests for a single module (module names are Gradle project paths, see `settings.gradle`):
```
./gradlew :kwik:test          # core module (project dir: core/)
./gradlew :kwik-qlog:test
./gradlew :kwik-h09:test
./gradlew :kwik-cli:test
```

Run a single test class or method:
```
./gradlew :kwik:test --tests "tech.kwik.core.recovery.LossDetectorTest"
./gradlew :kwik:test --tests "tech.kwik.core.recovery.LossDetectorTest.someTestMethod"
```

Note the module/directory naming mismatch: the `core` directory is the Gradle project named `kwik` (root
library artifact); `qlog`, `h09`, `cli`, `samples`, `interop` map to `kwik-qlog`, `kwik-h09`, `kwik-cli`,
`kwik-samples`, `kwik-interop` respectively (see `settings.gradle`).

Tests use JUnit 5 (Jupiter), Mockito (loaded as a Java agent, not self-attached — see
`buildSrc/.../buildlogic.java-common-conventions.gradle`), and AssertJ.

Project version is derived from `git describe --always --dirty` at build time (see the shared convention
plugin); there's no version to bump by hand in build files.

## Module structure

- `core` (artifact/module `kwik`, Java module `tech.kwik.core`) — the QUIC implementation itself: packet
  parsing/building, TLS handshake integration, loss recovery, congestion control, flow control, streams,
  connection ID management, client and server connection logic.
- `h09` (`kwik-h09`) — minimal HTTP/0.9 on top of Kwik, used by the CLI/interop runner when no HTTP/3 plugin
  (Flupke) is present.
- `qlog` — qlog event logging add-on; depends on `core`'s test utilities (via the `testArtifacts`
  configuration) to build its tests.
- `cli` (`kwik-cli`) — the `kwik`/`quic` command-line sample client (`tech.kwik.cli.KwikCli`), runnable via
  `kwik.sh` or `gradle run`.
- `samples` (`kwik-samples`) — example client/server code, including `SampleWebServer`.
- `interop` (`kwik-interop`) — the automated interoperability test runner (`tech.kwik.interop.InteropRunner`),
  not published.

Cross-module dependencies always go through `project(':kwik')` etc. (see each module's `build.gradle`), never
through relative source paths. Shared Gradle conventions (Java version, JUnit/Mockito/AssertJ deps, Maven
publishing setup) live in `buildSrc/src/main/groovy/buildlogic.java-common-conventions.gradle` and are applied
via `id 'buildlogic.java-common-conventions'` in each module's `build.gradle` — change shared build behavior
there, not per-module.

## Core module architecture

Within `core/src/main/java/tech/kwik/core/`:

- `impl/` — the connection state machines: `QuicConnectionImpl` (shared logic) and
  `QuicClientConnectionImpl` (client-specific); public-facing interfaces (`QuicConnection`,
  `QuicClientConnection`, `QuicStream`, `ConnectionConfig`) live one level up in `core/` itself and are what
  applications embedding Kwik are expected to use. `server/impl/` holds the analogous server-side connection
  machinery (`ServerConnectionImpl`, `ServerConnectorImpl`, packet-filter chain for anti-amplification/address
  validation/etc.), with public server SPI (`ApplicationProtocolConnectionFactory`,
  `ApplicationProtocolConnection`, `ServerConnector`) in `server/`.
- `packet/` — QUIC packet types (Initial, Handshake, 1-RTT, etc.) and a chain of `PacketFilter`/
  `DatagramFilter` implementations used to validate/preprocess incoming datagrams before dispatch.
  `PacketParser` is role-aware; `ClientRolePacketParser` is the client-side variant.
  `InitialPacketFilterProxy` composes server-side filters (dedup, min-size, address validation).
- `frame/` — individual QUIC frame types, each responsible for its own encode/decode/processing.
- `send/` — outgoing path: `SenderImpl` drives sending, `PacketAssembler`/`GlobalPacketAssembler` assemble
  frames into packets per encryption level, `SendRequestQueue` queues frame-send requests.
- `receive/` — incoming path: `Receiver` abstractions reading from the datagram socket into `RawPacket`s
  (`FixedAddressReceiver` vs `MultipleAddressReceiver`, the latter used when connection migration/multiple
  local addresses are involved).
- `recovery/` — loss detection and RTT: `LossDetector`, `RecoveryManager`, `RttEstimator`, tracked per packet
  number space (`PnSpace`: Initial/Handshake/App).
- `cc/` — congestion control implementations (`NewRenoCongestionController`, `FixedWindowCongestionController`)
  behind the `CongestionController` interface.
- `cid/` — connection ID lifecycle: `ConnectionIdManager` plus separate source/destination registries, used by
  both roles and central to connection migration support.
- `stream/` — QUIC stream implementation: `QuicStreamImpl`, send/receive buffering (`SendBuffer`,
  `ReceiveBufferImpl`, `RetransmitBuffer`), and flow control (`FlowControl`).
- `crypto/` — AEAD/cipher-suite implementations and `ConnectionSecrets`/`CryptoStream`, sitting on top of the
  external `agent15` TLS 1.3 library dependency (not implemented in this repo).
- `tls/` — the QUIC transport-parameters TLS extension.
- `path/` — path validation (PATH_CHALLENGE/PATH_RESPONSE), used for connection migration.
- `log/` — pluggable `Logger` (`SysOutLogger`, `FileLogger`, `NullLogger`); `QLog` is the separate structured
  qlog event interface, implemented by the `qlog` module.
- `socket/` — `SocketManager` abstractions wrapping `DatagramSocket` for client vs. server use.

Connections are built via builder APIs (`QuicClientConnection.newBuilder()`, `ServerConnector.builder()`) that
produce configured instances of the `impl` classes; most application-facing config objects
(`ClientConnectionConfig`, `ServerConnectionConfig`) also live in `impl`/`server` and are constructed through
builders rather than directly.

## Testing conventions

- Core exposes its test utilities to other modules via a `testArtifacts` Gradle configuration/`testJar` task
  (see `core/build.gradle`); consumers add `testImplementation(project(path: ':kwik', configuration:
  'testArtifacts'))` (as `qlog` does) to reuse them instead of duplicating mocks.
- Common test helpers live in `core/src/test/java/tech/kwik/core/test/` (e.g. `TestClock`,
  `TestScheduledExecutor`, `TestCertificates`, `FieldReader`/`FieldSetter` for reflection-based test setup) and
  `core/src/test/java/tech/kwik/core/impl/` (`TestUtils`, `MockPacket`).
- Test classes mirror the main package structure 1:1 under `core/src/test/java/tech/kwik/core/...`.
