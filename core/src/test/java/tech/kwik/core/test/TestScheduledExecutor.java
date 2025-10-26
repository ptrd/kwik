/*
 * Copyright © 2022, 2023, 2024, 2025 Peter Doornbosch
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
package tech.kwik.core.test;

import tech.kwik.core.impl.NotYetImplementedException;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.*;
import java.util.stream.Collectors;

/**
 * Deterministic scheduler to use in unit tests.
 * Note that this scheduler is not a complete implementation of ScheduledExecutorService! Only methods the needed to
 * be implemented to successfully execute the tests it is used in, are implemented.
 */
public class TestScheduledExecutor implements ScheduledExecutorService, TestClock.ClockListener {

    private TestClock clock;
    private List<ScheduledAction> scheduledActions;
    private boolean shutdown;

    public TestScheduledExecutor(TestClock clock) {
        this.clock = clock;
        this.scheduledActions = new ArrayList<>();
        clock.registerListener(this);
    }

    @Override
    public ScheduledFuture<?> schedule(Runnable command, long delay, TimeUnit unit) {
        long delayInMillis = unit.toMillis(delay);
        ScheduledAction action = new ScheduledAction(clock.instant().plusMillis(delayInMillis), command);
        scheduledActions.add(action);
        return new ActionFuture(action);
    }

    @Override
    public <V> ScheduledFuture<V> schedule(Callable<V> callable, long delay, TimeUnit unit) {
        throw new NotYetImplementedException();
    }

    @Override
    public ScheduledFuture<?> scheduleAtFixedRate(Runnable command, long initialDelay, long period, TimeUnit unit) {
        long delayInMillis = unit.toMillis(initialDelay);
        ScheduledAction action = new ScheduledAction(clock.instant().plusMillis(delayInMillis), new SelfRepeatingCommand(command, period, clock.instant().plusMillis(delayInMillis)));
        scheduledActions.add(action);
        return new ActionFuture(action);
    }

    @Override
    public ScheduledFuture<?> scheduleWithFixedDelay(Runnable command, long initialDelay, long delay, TimeUnit unit) {
        throw new NotYetImplementedException();
    }

    @Override
    public void shutdown() {
        shutdown = true;
        cancelAllScheduledActions();
    }

    @Override
    public List<Runnable> shutdownNow() {
        shutdown = true;
        return cancelAllScheduledActions();
    }

    @Override
    public boolean isShutdown() {
        return shutdown;
    }

    @Override
    public boolean isTerminated() {
        return false;
    }

    @Override
    public boolean awaitTermination(long timeout, TimeUnit unit) throws InterruptedException {
        return false;
    }

    @Override
    public <T> Future<T> submit(Callable<T> task) {
        throw new NotYetImplementedException();
    }

    @Override
    public <T> Future<T> submit(Runnable task, T result) {
        throw new NotYetImplementedException();
    }

    @Override
    public Future<?> submit(Runnable task) {
        return schedule(task, 0, TimeUnit.MILLISECONDS);
    }

    @Override
    public <T> List<Future<T>> invokeAll(Collection<? extends Callable<T>> tasks) throws InterruptedException {
        throw new NotYetImplementedException();
    }

    @Override
    public <T> List<Future<T>> invokeAll(Collection<? extends Callable<T>> tasks, long timeout, TimeUnit unit) throws InterruptedException {
        throw new NotYetImplementedException();
    }

    @Override
    public <T> T invokeAny(Collection<? extends Callable<T>> tasks) throws InterruptedException, ExecutionException {
        throw new NotYetImplementedException();
    }

    @Override
    public <T> T invokeAny(Collection<? extends Callable<T>> tasks, long timeout, TimeUnit unit) throws InterruptedException, ExecutionException, TimeoutException {
        throw new NotYetImplementedException();
    }

    @Override
    public void execute(Runnable command) {
        throw new NotYetImplementedException();
    }

    @Override
    public void clockAdvanced() {
        check();
    }

    public void check() {
        List<ScheduledAction> actionsToRun = scheduledActions.stream()
                .filter(action -> ! action.scheduledTime.isAfter(clock.instant()))  // almost equivalent to isBefore, except for when times match exactly
                .collect(Collectors.toList());
        scheduledActions.removeAll(actionsToRun);
        actionsToRun.forEach(a -> a.command.run());
    }

    private List<Runnable> cancelAllScheduledActions() {
        List<Runnable> commands = scheduledActions.stream().map(action -> action.command).collect(Collectors.toList());
        scheduledActions.clear();
        return commands;
    }

    public List<ScheduledAction> getScheduledActions() {
        return scheduledActions;
    }

    private static class ScheduledAction {
        final Instant scheduledTime;
        final Runnable command;

        public ScheduledAction(Instant scheduledTime, Runnable command) {
            this.scheduledTime = scheduledTime;
            this.command = command;
        }
    }

    private class ActionFuture<V> implements ScheduledFuture<V> {
        private final ScheduledAction action;

        public ActionFuture(ScheduledAction action) {
            this.action = action;
        }

        @Override
        public long getDelay(TimeUnit unit) {
            throw new NotYetImplementedException();
        }

        @Override
        public int compareTo(Delayed o) {
            throw new NotYetImplementedException();
        }

        @Override
        public boolean cancel(boolean mayInterruptIfRunning) {
            return scheduledActions.remove(action);
        }

        @Override
        public boolean isCancelled() {
            throw new NotYetImplementedException();
        }

        @Override
        public boolean isDone() {
            throw new NotYetImplementedException();
        }

        @Override
        public V get() throws InterruptedException, ExecutionException {
            throw new NotYetImplementedException();
        }

        @Override
        public V get(long timeout, TimeUnit unit) throws InterruptedException, ExecutionException, TimeoutException {
            throw new NotYetImplementedException();
        }
    }

    private class SelfRepeatingCommand implements Runnable {

        private final Runnable command;
        private final long period;
        private Instant scheduledTime;

        public SelfRepeatingCommand(Runnable command, long period, Instant initialRun) {
            this.command = command;
            this.period = period;
            scheduledTime = initialRun;
        }

        @Override
        public void run() {
            command.run();
            if (! shutdown) {
                scheduledTime = scheduledTime.plusMillis(period);
                ScheduledAction repeatAction = new ScheduledAction(scheduledTime, this);
                scheduledActions.add(repeatAction);
                check();
            }
        }
    }
}
