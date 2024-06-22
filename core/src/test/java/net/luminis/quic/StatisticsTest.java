package net.luminis.quic;

import net.luminis.quic.send.SendStatistics;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class StatisticsTest {

    @Test
    void whenComputedEfficiencyPercentageHasOneDecimalItIsReturned() {
        // Given
        SendStatistics sendStatistics = new SendStatistics(0, 0, 1000, 759, 0, 10, 1, 11);

        // When
        Statistics statistics = new Statistics(sendStatistics);

        // Then
        assertThat(statistics.efficiency()).isEqualTo(75.9f);
    }

    @Test
    void whenComputedEfficiencyPercentageHasMultipleDecimalsOnyTheFirstIsReturned() {
        // Given
        SendStatistics sendStatistics = new SendStatistics(0, 0, 10000, 7596, 0, 10, 1, 11);

        // When
        Statistics statistics = new Statistics(sendStatistics);

        // Then
        assertThat(statistics.efficiency()).isEqualTo(75.9f);
    }
}