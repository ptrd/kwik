/*
 * Copyright © 2019, 2020, 2021, 2022, 2023, 2024, 2025 Peter Doornbosch
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
package tech.kwik.core.concurrent;

import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Creates daemon threads. Java's default thread factory used in executors creates non-daemon threads that
 * prevent JVM from shutting down.
 */
public class DaemonThreadFactory implements ThreadFactory {

    private final String threadBaseName;
    private final AtomicInteger threadNumber = new AtomicInteger(1);
    private ThreadFactory virtualFactory;

    public DaemonThreadFactory(String threadBaseName) {
        this.threadBaseName = threadBaseName;

        if (Runtime.version().feature() >= 24) {
            try {
                var lookup = MethodHandles.lookup();
                var builderClass = Class.forName("java.lang.Thread$Builder$OfVirtual");
                // public static Builder.OfVirtual ofVirtual()
                var ofVirtualHandle =
                        lookup.findStatic(Thread.class, "ofVirtual", MethodType.methodType(builderClass));

                // 2. public Thread.Builder name(String prefix, long start)
                var nameHandle =
                        lookup.findVirtual(
                                builderClass,
                                "name",
                                MethodType.methodType(builderClass, String.class, long.class));

                // 3. Invoke Thread.ofVirtual().name(threadBaseName, 0)
                var namedBuilder = nameHandle.invoke(ofVirtualHandle.invoke(), threadBaseName, 0L);

                // 4. public ThreadFactory factory()
                var factoryHandle =
                        lookup.findVirtual(builderClass, "factory", MethodType.methodType(ThreadFactory.class));

                // 5. Invoke namedBuilder.factory()
                this.virtualFactory = (ThreadFactory) factoryHandle.invoke(namedBuilder);
            } catch (Throwable e) {
                // impossible
            }
        }
    }

    @Override
    public Thread newThread(Runnable runnable) {

        if (virtualFactory != null) {
            return virtualFactory.newThread(runnable);
        }

        Thread thread = new Thread(runnable, threadBaseName + "-" + threadNumber.getAndIncrement());
        thread.setDaemon(true);
        return thread;
    }
}
