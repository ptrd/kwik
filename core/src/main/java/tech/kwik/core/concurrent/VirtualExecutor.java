package tech.kwik.core.concurrent;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;

/**
 * Utility class to reflectively invoke the Executors.newThreadPerTaskExecutor static method using
 * the Method Handles API.
 */
public class VirtualExecutor {

  private static final boolean SUPPORTED = Runtime.version().feature() >= 24;

  private static MethodHandle handle;

  static {
    try {
      handle =
              MethodHandles.publicLookup()
                      .findStatic(
                              Executors.class,
                              "newThreadPerTaskExecutor",
                              MethodType.methodType(ExecutorService.class, ThreadFactory.class));
    } catch (Exception __) {
      // failing is of no consequence
    }
  }

  /** Returns true if virtual threads are supported in this JVM */
  public static boolean supported() {
    return SUPPORTED;
  }

  /**
   * Reflectively creates a virtual thread executor
   *
   * @param name the name of the threads
   * @return A new ExecutorService instance backed by virtual threads.
   */
  public static ExecutorService createExecutor(String name) {
    try {
      return (ExecutorService) handle.invoke(new DaemonThreadFactory(name));
    } catch (Throwable e) {
      throw new UnsupportedOperationException("this jvm doesn't support virtual threads");
    }
  }
}