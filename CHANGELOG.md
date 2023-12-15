# Releases

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
