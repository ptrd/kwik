package net.luminis.quic;

public class Statistics {

    long lost;
    private long sent;

    public long getLost() {
        return lost;
    }

    public void setLost(long lost) {
        this.lost = lost;
    }

    @Override
    public String toString() {
        return "Sent: " + sent + "; lost: " + lost;
    }

    public void setSent(long sent) {
        this.sent = sent;
    }

    public long getSent() {
        return sent;
    }
}
