# Releases

## 0.10.8 (2025-11-18)

- suppress warning message when packet can not be decrypted because of discarded keys
- added method to retrieve initial client address including port number
- fix: server connector builder should allow that port is not set when socket was set

## 0.10.7 (2025-10-30)

- several performance improvements
- fix a few issues w.r.t. exact packet length, which caused Kwik to fail to connect with servers that use a `max_udp_payload_size ` of 1200.

## 0.10.6 (2025-09-06)

- added another method to client connection builder to set key manager
- added system property to disable the check that initial packets should contain considerable amount of crypto data

## 0.10.5 (2025-08-31)

- added another method to client connection builder to set trust manager 

## 0.10.4 (2025-07-20)

- fix: regression that could cause endless loop in sender
- option (environment variable) to send probe as single (or double) ping frames
- command line option to set default stream receiver buffer size
- send RTT metrics to Qlog
- let server watch memory usage and log warnings when exceeding threshold of 85%
- log when stream gets blocked or unblocked

## 0.10.3 (2025-06-03)

- fix: aborting connection (e.g. on network error) leading to incorrect internal state causing an assert to fail
  [issue 60](https://github.com/ptrd/kwik/issues/60)
- added option to suppress warning about insecure configuration (disabled certificate validation) with system property
  (`-Dtech.kwik.core.no-security-warnings=true`)

## 0.10.2 (2025-04-25)

- small improvents in Interop test runner
- add getters to `Statistics` class to expose send statistics
  [issue 65](https://github.com/ptrd/kwik/issues/65)
- use `com.io7m.repackage.io.whitfin:io.whitfin.siphash` instead of `io.whitfin:siphash` because it has Java module support
  [issue 63](https://github.com/ptrd/kwik/issues/63), [issue 59](https://github.com/ptrd/kwik/issues/59)
- upgrade agent15 to 3.1 to fix issue with signature algorithm on Android
  [issue 62](https://github.com/ptrd/kwik/issues/62)
- improved error logging
- generate connection errors for error situations as prescribed by RFC9000

## 0.10.1 (2025-02-18)

- better distinguish between variable length integers whose size is plain wrong or whose size is not supported by Kwik
- fix: serialization of connection close frame of type 0x1d
- respond with connection error when a packet contains a frame type that is not permitted 
- respond with connection error to situations as unknown frame, invalid frame encoding, and a lot more
- do not create a server connection before a complete and valid Client Hello message is received
- use siphash for key in connection table

## 0.10 (2025-01-10)

**Note: this release has a breaking change (which is, however, easy to fix)**

Changed package structure: all packages now start with `tech.kwik`.

**Upgrade instructions:** if your project is only using the `tech.kwik.core` module (`kwik.jar`), which will usually be the case, upgrading is as simple as performing a global find-and-replace to replace the string `net.luminis.quic` by `tech.kwik.core`.
Only in case your project is also using other kwik dependencies, read on, because then you should do other replacements first.

If your project is using other kwik modules besides kwik core:

- if using `kwik-cli`: replace `net.luminis.quic.cli` by `tech.kwik.cli`
- if using `kwik-qlog`: replace `net.luminis.quic.qlog` by `tech.kwik.qlog`
- if using `kwik-samples`; replace `net.luminis.quic.sample` by `tech.kwik.sample`
- if using `kwik-interop`: replace `net.luminis.quic.interop` by `tech.kwik.interop`
- if using `kwik-h09`:
  - replace: `net.luminis.quic.client.h09` by `tech.kwik.h09.client`
  - replace: `net.luminis.quic.server.h09` by `tech.kwik.h09.server`
  - replace: `net.luminis.quic.io` by `tech.kwik.h09.io`
- and finally replace `net.luminis.quic` by `tech.kwik.core`.

Because in this release also the agent15 version is upgraded to 3.0, you might need to also do a find-and-replace to
replace `net.luminis.tls` by `tech.kwik.agent15`, for example when setting a specific cipher using the `Builder.cipherSuite` method.

Other (minor) changes:
- fix: bug in connection flow control check
- introduced retransmit buffer to ensure stream data can always be retransmitted, even when packets get smaller
- fix: key update with aes256gcm
- fix: inconsistent congestion control state with retry 
- added option to enforce the max (receive) udp payload size
- added option to enforce strict smallest allowed maximum package size (i.e. 1200 bytes)
- let max packet size depend on IP version
- option to set IP version preference

## 0.9.1 (2024-11-14)

- added `close` method to properly shut down a ServerConnector (including closing all connections and free all resources).
  [issue 44](https://github.com/ptrd/kwik/issues/44)
- improved handling of closing the connection while it is still handshaking
- added ConnectionListener for reacting to connection established / connection terminated events
  [issue 48](https://github.com/ptrd/kwik/issues/48)

## 0.9 (2024-11-04)

Added support for "Unreliable Datagram Extension", [RFC 9221](https://www.rfc-editor.org/rfc/rfc9221.html)

Other improvements and bug fixes:
- ServerConnector.build() now throws specific exceptions rather than generic Exception [issue 52](https://github.com/ptrd/kwik/issues/52)
- fix: bug with max stream id [issue 51](https://github.com/ptrd/kwik/issues/51)
- fix: packet coalesced with first initial was not parsed / processed (reported by Lars Eggert, QUIC interop)
- two fixes in (TLS) handshake: corrected the way the server selects the signature algorithm
  and let client offer all signature algorithms it supports in cryptographic negotiation.

## 0.8.13 (2024-07-02)

- defined Java modules
- upgraded agent15 to 2.0 (defining Java module)
- removed dependency on ByteUtils class from agent15
- moved all server implementation classes to a separate package (net.luminis.quic.server.impl)
- changed ServerConnector and ServerConnectionConfig into an interface
- removed Version class from public interfaces/classes ServerConnector and SampleWebServer
- moved class KwikVersion to net.luminis.quic
- moved enums EncryptionLevel and PnSpace to net.luminis.quic.common
- moved all classes from package net.luminis.quic.core (except EncryptionLevel and PnSpace), to net.luminis.quic.impl 
- moved Range class to package net.luminis.quic.frame

## 0.8.12 (2024-06-22)

Split source code into separate modules, making dependencies more specific (e.g. the core module no longer has a 
dependency on `commons-cli`). To enable this change, some classes were moved to other packages.

- moved SampleWebServer to package net.luminis.quic.sample
- moved KwikCli to package net.luminis.quic.cli
- moved InteropRunner and InteropServer to package net.luminis.quic.interop
- moved QlogPacketFilter to package net.luminis.quic.packet
- moved QLog to package net.luminis.quic.qlog
- replaced old javax.json lib by jakarta EE version
- rewrote the `kwik.sh` script

## 0.8.11 (2024-05-28)

- upgraded agent15 to 1.1 (accepting ECDSA certificates for server identification)
- accept ECDSA certificates for client authentication
- added options to provide server and client certificate as well as client truststore as Java key store objects
- large refactor involving processor chain for processing datagrams / packets
- drop duplicate packets (as mandated by RFC 9000)
- log parse error caused by discarded keys as warning, not as error
- fixed two situations where a runtime exception might occur

## 0.8.10 (2024-03-03)

- Upgraded agent15 to 1.0.6
- Fix NPE in stream handling

## 0.8.9 (2024-01-01)

Deprecated connection method `setDefaultStreamReceiveBufferSize()` and replaced it by a specific one for each stream type (unidirectional/bidirectional).  

## 0.8.8 (2023-12-29)

- Server connection settings are now determined by combination of server configuration and protocol requirements, 
  see [the readme](readme.md) for explanation and example(s).
- Reading or writing the "wrong" side of a unidirectional stream will now fail. 
- Two fixes with respect to ack delay.

## 0.8.7 (2023-12-19)

Fixed path challenge denial of service vulnerability

## 0.8.6 (2023-12-16)

- discard all incoming data for a stream that has been reset 
- handle flow control credits correctly when stream is reset 
- fixed that final size of closed streams was not included in flow control credits computation (which allowed malicious peers to use more credits than allowed)

## 0.8.5 (2023-12-12)

Lots of fixes w.r.t. stream handling:
- avoid (stream) frames to be sent after connection is aborted
- refuse incoming stream data for self-initiated (send-only) unidirectional stream
- fix: server allowed one more stream than configured
- prevent closed streams from being reopened
- fix stream id generation
- check for final size errors
- clear send and/or receive buffer when a stream is terminated to other reason than normal close
- fixed that new streams could be earned by just sending a final frame
- lots of small bug fixes indicated by static analysis (Error Prone)

## 0.8.4 (2023-12-02)

- Enforce flow control limits
- Better server side logging of connections being closed
- New receive buffer implementation, both for crypto and plain data, that is more memory efficient in relation to badly
  behaving clients
- Fix: cleanup server connection when closed

## 0.8.3 (2023-11-06)

Relocated maven artifact to `tech.kwik` group id.

## 0.8.2 (2023-11-05)

No changes, corrected pom.

## 0.8.1 (2023-11-04)

- Updated agent15 dependency.
- Updated test dependencies and HKDF library.
- Corrected pom.
- Corrected reference to flupke jar in shell script.

## 0.8 (2023-10-08)

First official release published to maven.
