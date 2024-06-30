# Releases

## WIP

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
