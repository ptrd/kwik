package tech.kwik.core.cc;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import tech.kwik.core.log.NullLogger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class NewRenoCongestionControllerMaxDatagramSizeTest {

    private NewRenoCongestionController cc;

    @BeforeEach
    void setUp() {
        cc = new NewRenoCongestionController(new NullLogger(), mock(CongestionControlEventListener.class));
    }

    @Test
    void cwndScalesProportionally() {
        cc.updateMaxDatagramSize(1400);
        assertThat(cc.getWindowSize()).isEqualTo(12_000L * 1400 / 1200);
    }

    @Test
    void cwndNeverDropsBelowMinimum() {
        cc.updateMaxDatagramSize(100);
        assertThat(cc.getWindowSize()).isGreaterThanOrEqualTo(200);
    }
}
