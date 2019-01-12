package net.luminis.quic;

/**
 * A simplistic static congestion controller, that does not allow more than approx. one packetsize in flight.
 */
public class CongestionController {

    private final Logger log;
    private final Object lock = new Object();

    private int bytesInFlight;
    private int congestionWindow;


    public CongestionController(Logger logger) {
        this.log = logger;
        congestionWindow = 1250;  // i.e. approx 1 max packet size
    }

    public synchronized boolean canSend(QuicPacket packet) {
        return bytesInFlight + packet.getBytes().length < congestionWindow;
    }

    public synchronized void registerAcked(QuicPacket acknowlegdedPacket) {
        bytesInFlight -= acknowlegdedPacket.getBytes().length;
        log.debug("Bytes in flight decreased to " + bytesInFlight);
        synchronized (lock) {
            lock.notifyAll();
        }
    }

    public synchronized void registerInFlight(QuicPacket sentPacket) {
        bytesInFlight += sentPacket.getBytes().length;
        log.debug("Bytes in flight increased to " + bytesInFlight);
        synchronized (lock) {
            lock.notifyAll();
        }
    }

    public void waitForUpdate() throws InterruptedException {
        synchronized (lock) {
            lock.wait();
        }
    }
}
