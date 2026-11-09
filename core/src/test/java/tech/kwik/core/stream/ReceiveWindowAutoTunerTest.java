package tech.kwik.core.stream;

import org.junit.jupiter.api.Test;
import java.util.Random;
import static org.assertj.core.api.Assertions.*;

class ReceiveWindowAutoTunerTest {
    @Test
    void growsUnderSustainedDemandAndHonorsTheMaximum() {
        ReceiveWindowAutoTuner tuner = new ReceiveWindowAutoTuner(65_536, 65_536, 262_144, 0);
        long now = 0;
        for (int i = 0; i < 8; i++) {
            long window = tuner.window();
            now += 100_000_000;
            tuner.consumed((int) window, 0, now, 100_000_000);
        }
        assertThat(tuner.window()).isEqualTo(262_144);
    }

    @Test
    void reducesTheTargetGraduallyWhenTheConsumerFallsBehind() {
        ReceiveWindowAutoTuner tuner = new ReceiveWindowAutoTuner(262_144, 65_536, 262_144, 0);
        for (int i = 1; i <= 10; i++) {
            long before = tuner.window();
            long after = tuner.consumed(1_024, 65_536, i * 200_000_000L, 50_000_000);
            assertThat(after).isBetween(Math.max(65_536, before - before / 4), before);
        }
        assertThat(tuner.window()).isEqualTo(65_536);
    }

    @Test
    void doesNotTreatIdleTimeAsPoorBandwidth() {
        ReceiveWindowAutoTuner tuner = new ReceiveWindowAutoTuner(262_144, 65_536, 262_144, 0);
        assertThat(tuner.consumed(100, 0, 60_000_000_000L, 100_000_000)).isEqualTo(262_144);
        assertThat(tuner.consumed(100, 0, 60_200_000_000L, 100_000_000)).isEqualTo(262_144);
    }

    @Test
    void waitsForEnoughEvidenceAndHandlesClockWrap() {
        ReceiveWindowAutoTuner tuner = new ReceiveWindowAutoTuner(65_536, 65_536, 262_144, Long.MAX_VALUE - 10);
        assertThat(tuner.consumed(65_536, 0, Long.MIN_VALUE + 20, 100_000_000)).isEqualTo(65_536);
        assertThat(tuner.consumed(65_536, 0, Long.MIN_VALUE + 100_000_020, 0)).isEqualTo(65_536);
    }

    @Test
    void rejectsInvalidBounds() {
        assertThatThrownBy(() -> new ReceiveWindowAutoTuner(1_024, 0, 65_536, 0)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new ReceiveWindowAutoTuner(1_024, 8_192, 1_024, 0)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new ReceiveWindowAutoTuner(1_024, 1_024, Long.MAX_VALUE, 0)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void staysBoundedAcrossChangingRatesRttAndBacklog() {
        Random random = new Random(7251);
        ReceiveWindowAutoTuner tuner = new ReceiveWindowAutoTuner(65_536, 65_536, 262_144, 0);
        long now = 0;
        for (int i = 0; i < 10_000; i++) {
            now += (1L + random.nextInt(2_000)) * 1_000_000;
            long window = tuner.consumed(1 + random.nextInt(262_144), random.nextInt(262_144), now,
                (1L + random.nextInt(2_000)) * 1_000_000);
            assertThat(window).isBetween(65_536L, 262_144L);
        }
    }
}
