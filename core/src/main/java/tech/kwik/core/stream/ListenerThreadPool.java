package tech.kwik.core.stream;

import tech.kwik.core.concurrent.VirtualExecutor;

import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;

import static java.lang.Thread.currentThread;
import static java.util.concurrent.Executors.newSingleThreadExecutor;
import static java.util.concurrent.TimeUnit.DAYS;

final class ListenerThreadPool implements Executor, AutoCloseable {
	
    private final ExecutorService executor;
	private final boolean virtual;

    ListenerThreadPool() {
		if (VirtualExecutor.supported()) {
			this.executor = VirtualExecutor.createExecutor("kwik-listener");
			this.virtual = true;
			return;
		}
        this.executor = newSingleThreadExecutor(runnable -> {
			Thread thread = new Thread(runnable, "kwik-listener");
			thread.setDaemon(true);
			return thread;
		});
		this.virtual = false;
    }
	
	@Override
	public void execute(Runnable command) {
		this.executor.execute(command);
	}
	
    /**
     * Implementation of {@link AutoCloseable#close()} that performs an
     * orderly shutdown of {@link #executor}.
     *
     * @implNote This is a clone of OpenJDK 19+ default close method
     * available directly on the newer {@code ExecutorService} interface.
     */
    @Override
    public void close() {
		if (this.virtual) return;
		
        boolean terminated = this.executor.isTerminated();
		if (terminated) return;
  
		this.executor.shutdown();
		boolean interrupted = false;
		while (!terminated) {
			try {
				terminated = this.executor.awaitTermination(1L, DAYS);
			} catch (InterruptedException e) {
				if (interrupted) continue;
				this.executor.shutdownNow();
				interrupted = true;
			}
		}
		if (!interrupted) return;
		currentThread().interrupt();
	}
}
