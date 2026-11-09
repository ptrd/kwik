package tech.kwik.core.stream;

final class ReceiveWindowAutoTuner {
    private final long minimum;
    private final long maximum;
    private long window;
    private long sampleStarted;
    private long consumed;

    ReceiveWindowAutoTuner(long initial, long minimum, long maximum, long now) {
        if (minimum < 1024 || maximum < minimum || maximum > (1L << 62) - 1) {
            throw new IllegalArgumentException("Invalid receive window bounds");
        }
        this.minimum = minimum;
        this.maximum = maximum;
        window = Math.max(minimum, Math.min(maximum, initial));
        sampleStarted = now;
    }

    long consumed(int bytes, long buffered, long now, long rttNanos) {
        long elapsed = now - sampleStarted;
        if (elapsed < 0 || rttNanos <= 0 || (elapsed > Math.max(1_000_000_000L, 8L * rttNanos) && buffered == 0)) {
            sampleStarted = now;
            consumed = 0;
            return window;
        }
        consumed += bytes;
        if (elapsed < Math.max(100_000_000L, 2L * rttNanos)) {
            return window;
        }
        long target = Math.max(minimum, Math.min(maximum, (long) (2.0 * consumed * rttNanos / elapsed)));
        if (target > window) {
            window = Math.min(target, window > maximum / 2 ? maximum : 2 * window);
        } else if (buffered > 0 && target < window - window / 8) {
            window = Math.max(target, window - window / 4);
        }
        sampleStarted = now;
        consumed = 0;
        return window;
    }

    long window() {
        return window;
    }
}
