package tech.kwik.core.send;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import tech.kwik.core.frame.QuicFrame;
import tech.kwik.core.log.NullLogger;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class PmtuDiscoveryTest {

    private PmtuDiscovery pmtuDiscovery;
    private int lastMaxPacketSize;
    private List<QuicFrame[]> sentProbes;

    @BeforeEach
    void setUp() {
        lastMaxPacketSize = 0;
        sentProbes = new ArrayList<>();
        pmtuDiscovery = new PmtuDiscovery(new NullLogger(), size -> lastMaxPacketSize = size, size -> {}, (frames, lostCb) -> sentProbes.add(frames));
    }

    @Test
    void startBeginsSearchWhenPeerAllowsLargerPackets() {
        pmtuDiscovery.start(1452);
        assertThat(pmtuDiscovery.getState()).isEqualTo(PmtuDiscovery.State.Searching);
        assertThat(sentProbes).hasSize(1);
    }

    @Test
    void startStaysDisabledWhenPeerMaxIsTooSmall() {
        pmtuDiscovery.start(1200);
        assertThat(pmtuDiscovery.getState()).isEqualTo(PmtuDiscovery.State.Disabled);
    }

    @Test
    void acknowledgedProbeIncreasesPlpmtu() {
        pmtuDiscovery.start(1452);
        int probe = pmtuDiscovery.getProbeSize();
        pmtuDiscovery.probeAcknowledged(probe);
        assertThat(pmtuDiscovery.getCurrentPlpmtu()).isEqualTo(probe);
        assertThat(lastMaxPacketSize).isEqualTo(probe);
    }

    @Test
    void searchCompletesAtPeerMax() {
        pmtuDiscovery.start(1260);
        pmtuDiscovery.probeAcknowledged(pmtuDiscovery.getProbeSize());
        assertThat(pmtuDiscovery.getState()).isEqualTo(PmtuDiscovery.State.SearchComplete);
    }

    @Test
    void threeFailedProbesCompleteSearch() {
        pmtuDiscovery.start(1452);
        int probe = pmtuDiscovery.getProbeSize();
        pmtuDiscovery.probeLost(probe);
        pmtuDiscovery.probeLost(probe);
        pmtuDiscovery.probeLost(probe);
        assertThat(pmtuDiscovery.getState()).isEqualTo(PmtuDiscovery.State.SearchComplete);
        assertThat(pmtuDiscovery.getCurrentPlpmtu()).isEqualTo(1200);
    }

    @Test
    void partialSuccessKeepsLastGoodSize() {
        pmtuDiscovery.start(1452);
        int first = pmtuDiscovery.getProbeSize();
        pmtuDiscovery.probeAcknowledged(first);
        int second = pmtuDiscovery.getProbeSize();
        pmtuDiscovery.probeLost(second);
        pmtuDiscovery.probeLost(second);
        pmtuDiscovery.probeLost(second);
        assertThat(pmtuDiscovery.getCurrentPlpmtu()).isEqualTo(first);
    }

    @Test
    void fullSearchConverges() {
        pmtuDiscovery.start(1452);
        while (pmtuDiscovery.getState() == PmtuDiscovery.State.Searching) {
            pmtuDiscovery.probeAcknowledged(pmtuDiscovery.getProbeSize());
        }
        assertThat(pmtuDiscovery.getCurrentPlpmtu()).isGreaterThan(1200);
        assertThat(pmtuDiscovery.getCurrentPlpmtu()).isLessThanOrEqualTo(1452);
    }
}
