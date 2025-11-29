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
package tech.kwik.interop;

import java.lang.management.ManagementFactory;
import java.lang.management.ThreadInfo;
import java.lang.management.ThreadMXBean;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.stream.Collectors;

public class WatchDog {

    private Thread watcherThread;
    private int maxRuntime;

    public WatchDog(int maxRuntimeInSeconds) {
        this.maxRuntime = maxRuntimeInSeconds;
    }

    public void start() {
        watcherThread = new Thread(this::run);
        watcherThread.setDaemon(true);
        watcherThread.start();
    }

    private void run() {
        Instant startTime = Instant.now();
        int reportInterval = 29; // seconds

        while (true) {
            try {
                if (Duration.between(startTime, Instant.now()).toSeconds() >= maxRuntime) {
                    abort();
                }
                Thread.sleep(Integer.min(reportInterval, maxRuntime - (int)Duration.between(startTime, Instant.now()).toSeconds()) * 1000L);
                log("WatchDog: system running for " + Duration.between(startTime, Instant.now()).toSeconds() + " seconds.");
            }
            catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
            catch (Exception e) {
                log("WatchDog: Exception occurred: " + e.getMessage());
                abort();
            }
        }
        log("WatchDog: terminated normally after " + Duration.between(startTime, Instant.now()).toSeconds() + " seconds.");
    }

    public void end() {
        watcherThread.interrupt();
    }

    private void abort() {
        log("WatchDog: Maximum runtime reached. Aborting. Thread dump follows.");

        ThreadMXBean bean = ManagementFactory.getThreadMXBean();
        ThreadInfo[] infos = bean.dumpAllThreads(true, true);
        System.out.println(Arrays.stream(infos).map(Object::toString).collect(Collectors.joining()));

        System.exit(1);
    }

    private void log(String message) {
        System.out.println("[" + Instant.now() + "] " + message);
    }
}
