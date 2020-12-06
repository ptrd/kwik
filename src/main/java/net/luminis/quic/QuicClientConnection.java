package net.luminis.quic;

import net.luminis.quic.stream.QuicStream;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.function.Consumer;


public interface QuicClientConnection extends QuicConnection {

    void connect(int connectionTimeout) throws IOException;

    void connect(int connectionTimeout, TransportParameters transportParameters) throws IOException;

    List<QuicStream> connect(int connectionTimeout, String applicationProtocol, TransportParameters transportParameters, List<StreamEarlyData> earlyData) throws IOException;

    void keepAlive(int seconds);

    List<QuicSessionTicket> getNewSessionTickets();

    InetSocketAddress getLocalAddress();

    List<X509Certificate> getServerCertificateChain();

    class StreamEarlyData {
        byte[] data;
        boolean closeOutput;

        public StreamEarlyData(byte[] data, boolean closeImmediately) {
            this.data = data;
            closeOutput = closeImmediately;
        }
    }
}
