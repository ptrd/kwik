package tech.kwik.core.send;

import tech.kwik.core.frame.Padding;
import tech.kwik.core.frame.PingFrame;
import tech.kwik.core.frame.QuicFrame;
import tech.kwik.core.log.Logger;

import java.time.Duration;
import java.time.Instant;
import java.util.function.BiConsumer;
import java.util.function.Consumer;
import java.util.function.IntConsumer;

public class PmtuDiscovery {

    public enum State {
        Disabled,
        Base,
        Searching,
        SearchComplete
    }

    private static final int BASE_PLPMTU = 1200;
    private static final int MAX_PROBES = 3;
    private static final int PROBE_STEP = 50;
    private static final Duration PROBE_TIMEOUT = Duration.ofMillis(1500);
    private static final int ABSOLUTE_MAX_PLPMTU = 1452;
    private static final int SHORT_HEADER_OVERHEAD = 26;

    private final int maxPlpmtu;
    private final Logger log;
    private final IntConsumer maxPacketSizeUpdater;
    private final IntConsumer maxDatagramSizeUpdater;
    private final BiConsumer<QuicFrame[], Consumer<QuicFrame>> probeSender;

    private volatile State state;
    private volatile int currentPlpmtu;
    private volatile int probeSize;
    private volatile int probeCount;
    private volatile Instant lastProbeTime;
    private int peerMaxUdpPayloadSize;

    public PmtuDiscovery(Logger log, IntConsumer maxPacketSizeUpdater, IntConsumer maxDatagramSizeUpdater, BiConsumer<QuicFrame[], Consumer<QuicFrame>> probeSender) {
        this(log, maxPacketSizeUpdater, maxDatagramSizeUpdater, probeSender, ABSOLUTE_MAX_PLPMTU);
    }

    public PmtuDiscovery(Logger log, IntConsumer maxPacketSizeUpdater, IntConsumer maxDatagramSizeUpdater, BiConsumer<QuicFrame[], Consumer<QuicFrame>> probeSender, int maxPlpmtu) {
        this.log = log;
        this.maxPacketSizeUpdater = maxPacketSizeUpdater;
        this.maxDatagramSizeUpdater = maxDatagramSizeUpdater;
        this.probeSender = probeSender;
        this.maxPlpmtu = maxPlpmtu > BASE_PLPMTU ? maxPlpmtu : ABSOLUTE_MAX_PLPMTU;
        this.state = State.Disabled;
        this.currentPlpmtu = BASE_PLPMTU;
        this.peerMaxUdpPayloadSize = this.maxPlpmtu;
    }

    public void start(int peerMaxUdpPayloadSize) {
        this.peerMaxUdpPayloadSize = Math.min(peerMaxUdpPayloadSize, maxPlpmtu);
        if (this.peerMaxUdpPayloadSize <= BASE_PLPMTU) {
            state = State.Disabled;
            return;
        }
        state = State.Base;
        currentPlpmtu = BASE_PLPMTU;
        probeSize = Math.min(BASE_PLPMTU + PROBE_STEP, this.peerMaxUdpPayloadSize);
        probeCount = 0;
        sendProbe();
    }

    public synchronized void probeAcknowledged(int ackedProbeSize) {
        if (state != State.Searching && state != State.Base) return;

        currentPlpmtu = ackedProbeSize;
        maxPacketSizeUpdater.accept(currentPlpmtu);
        maxDatagramSizeUpdater.accept(currentPlpmtu);
        log.debug("PMTU: " + currentPlpmtu);

        int nextProbeSize = currentPlpmtu + PROBE_STEP;
        if (nextProbeSize > peerMaxUdpPayloadSize) {
            state = State.SearchComplete;
            return;
        }

        state = State.Searching;
        probeSize = nextProbeSize;
        probeCount = 0;
        sendProbe();
    }

    public synchronized void probeLost(int lostProbeSize) {
        if (state != State.Searching && state != State.Base) return;

        probeCount++;
        if (probeCount >= MAX_PROBES) {
            state = State.SearchComplete;
            maxPacketSizeUpdater.accept(currentPlpmtu);
            return;
        }
        sendProbe();
    }

    public synchronized void checkProbeTimeout() {
        if (state != State.Searching && state != State.Base) return;
        if (lastProbeTime == null) return;

        if (Duration.between(lastProbeTime, Instant.now()).compareTo(PROBE_TIMEOUT) > 0) {
            probeLost(probeSize);
        }
    }

    private void sendProbe() {
        if (probeSize > peerMaxUdpPayloadSize) {
            state = State.SearchComplete;
            return;
        }
        state = State.Searching;
        lastProbeTime = Instant.now();
        int paddingNeeded = probeSize - SHORT_HEADER_OVERHEAD - 1;
        QuicFrame ping = new PingFrame();
        QuicFrame padding = new Padding(Math.max(0, paddingNeeded));
        int targetSize = probeSize;
        probeSender.accept(new QuicFrame[]{ping, padding}, f -> probeLost(targetSize));
    }

    public State getState() {
        return state;
    }

    public int getCurrentPlpmtu() {
        return currentPlpmtu;
    }

    public int getProbeSize() {
        return probeSize;
    }

}
