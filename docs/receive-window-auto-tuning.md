# Optional receive-window auto-tuning

Applications can call `QuicStream.enableReceiveWindowAutoTuning(minimum, maximum)` once on a readable stream. Existing applications retain the fixed sliding receive window unless they opt in. `getReceiveWindowSize()` returns the current target, or the configured initial window when tuning is disabled. Implementations that do not support these optional methods throw `UnsupportedOperationException`.

Both bounds are byte counts. The minimum must be at least 1024, the maximum must be at least the minimum and must not exceed either the connection receive-buffer budget or QUIC's 62-bit offset limit. Enabling tuning on a closed, aborted, reset or already configured input fails. A stream without an input direction does not support tuning.

The estimator uses bytes consumed by the application and the connection's smoothed RTT. It samples over at least 100 ms and two RTTs, aiming for twice the observed consumption bandwidth-delay product. Each update grows the target by at most two times or shrinks it by at most one quarter. Shrinking requires backlog and a target reduction greater than one eighth; idle periods without backlog do not shrink the window. This estimates receive demand, not the physical capacity of the network.

Previously advertised offsets remain valid. Shrinking the target withholds additional credit until consumption catches up; it cannot reclaim credit already granted to the peer. MAX_STREAM_DATA offsets never decrease. The connection's configured total buffer budget still applies, and connection credit advances by bytes actually consumed.

Connection and stream credit are sent after releasing the receive monitor. The new tests cover bounded growth, gradual shrinking, idle periods, changing RTT/rate/backlog, offset monotonicity, connection-budget validation, invalid reconfiguration and credit callbacks that immediately deliver more data.

This feature does not change congestion control, add packet pacing or discover path MTU. Applications should choose bounds for their own latency and memory requirements.
