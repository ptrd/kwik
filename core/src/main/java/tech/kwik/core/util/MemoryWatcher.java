/*
 * Copyright © 2025 Peter Doornbosch
 *
 * This file is part of Kwik, an implementation of the QUIC protocol in Java.
 *
 * Kwik is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your option)
 * any later version.
 *
 * Kwik is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for
 * more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
package tech.kwik.core.util;

import tech.kwik.core.log.Logger;

import javax.management.NotificationEmitter;
import java.lang.management.*;
import java.time.Duration;
import java.time.Instant;

/**
 * MemoryWatcher monitors the heap memory usage and logs warnings when the usage exceeds a specified threshold.
 */
public class MemoryWatcher {

    public static final int MIN_LOG_INTERVAL_SECONDS = 5;
    public static final int MIN_PERCENTAGE_DELTA = 3;

    private Instant lastLoggedNotificationTime = Instant.EPOCH;
    private int lastLoggedMemoryUsage = 0;

    public MemoryWatcher(int notificationThreshold, Logger log) {
        ManagementFactory.getMemoryPoolMXBeans().stream()
                .filter(pool -> pool.getType() == MemoryType.HEAP && pool.isUsageThresholdSupported())
                .forEach(pool -> registerMemoryPool(pool, notificationThreshold, log));
    }

    private void registerMemoryPool(MemoryPoolMXBean pool, int notificationThreshold, Logger log) {
        log.info("Registering memory pool " + pool.getName() + " for usage notifications");
        int threshold = (int) Math.floor(pool.getUsage().getMax() / 100.0 * notificationThreshold);
        pool.setCollectionUsageThreshold(threshold);

        MemoryMXBean mbean = ManagementFactory.getMemoryMXBean();
        if (mbean instanceof NotificationEmitter) {
            NotificationEmitter emitter = (NotificationEmitter) mbean;
            emitter.addNotificationListener((notification, handback) -> {
                String notificationType = notification.getType();
                if (notificationType.equals(MemoryNotificationInfo.MEMORY_COLLECTION_THRESHOLD_EXCEEDED)) {
                    reportMemoryUsage(pool, log);
                }
            }, null, null);
        }
    }

    private void reportMemoryUsage(MemoryPoolMXBean pool, Logger log) {
        int percentage = convertToPercentage(pool.getCollectionUsage());
        if (Duration.between(lastLoggedNotificationTime, Instant.now()).toSeconds() > MIN_LOG_INTERVAL_SECONDS
                || Math.abs(percentage - lastLoggedMemoryUsage) >= MIN_PERCENTAGE_DELTA) {
            String msg = String.format("Memory usage exceeded threshold (%s): %d%%", pool.getName(), percentage);
            log.warn(msg);
            lastLoggedNotificationTime = Instant.now();
            lastLoggedMemoryUsage = percentage;
        }
    }

    private static int convertToPercentage(MemoryUsage memoryUsage) {
        return (int) (memoryUsage.getUsed() * 100 / memoryUsage.getMax());
    }
}
