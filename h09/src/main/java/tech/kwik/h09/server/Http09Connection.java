/*
 * Copyright © 2020, 2021, 2022, 2023, 2024, 2025 Peter Doornbosch
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
package tech.kwik.h09.server;

import tech.kwik.core.KwikVersion;
import tech.kwik.core.QuicConnection;
import tech.kwik.core.QuicConstants;
import tech.kwik.core.QuicStream;
import tech.kwik.core.StreamClosedException;
import tech.kwik.core.server.ApplicationProtocolConnection;
import tech.kwik.h09.io.LimitExceededException;
import tech.kwik.h09.io.LimitedInputStream;

import java.io.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


public class Http09Connection implements ApplicationProtocolConnection {

    public static final int MAX_REQUEST_SIZE = 4096;

    private static AtomicInteger threadCount = new AtomicInteger();

    private final QuicConnection connection;
    private final File wwwDir;

    public Http09Connection(QuicConnection quicConnection, File wwwDir) {
        this.wwwDir = wwwDir;
        this.connection = quicConnection;
    }

    @Override
    public void acceptPeerInitiatedStream(QuicStream quicStream) {
        Thread thread = new Thread(() -> handleRequest(quicStream));
        thread.setName("http-" + threadCount.getAndIncrement());
        thread.start();
    }

    void handleRequest(QuicStream quicStream) {
        try (InputStream inputStream = quicStream.getInputStream();
             OutputStream outputStream = quicStream.getOutputStream()) {
            String fileName = extractPathFromRequest(inputStream);
            if (fileName != null) {
                File file = getFileInWwwDir(fileName);
                if (file != null && file.exists() && file.isFile() && file.canRead()) {
                    try (FileInputStream fileInputStream = new FileInputStream(file)) {
                        fileInputStream.transferTo(outputStream);
                    }
                }
                else {
                    try (OutputStreamWriter outputStreamWriter = new OutputStreamWriter(outputStream)) {
                        if (fileName.equals("version") || fileName.equals("version.txt")) {
                            outputStreamWriter.write("Kwik version/build number: " + KwikVersion.getVersion() + "\n");
                        }
                        else {
                            outputStreamWriter.write("404: file '" + fileName + "' not found\n");
                        }
                    }
                }
            }
            else {
                System.out.println("Error: cannot extract file name");
            }
        }
        catch (LimitExceededException requestToLarge) {
            // Instead of closing the connection, the stream cloud be closed (which currently requires these two calls)
            // quicStream.closeInput(962);
            // quicStream.resetStream(785);
            connection.close(QuicConstants.TransportErrorCode.APPLICATION_ERROR, "Request too large");
        }
        catch (StreamClosedException e) {
            // Bad luck, the stream was closed while we were reading from it.
        }
        catch (IOException e) {
            connection.close(QuicConstants.TransportErrorCode.APPLICATION_ERROR, e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * Check that file specified by argument is actually in the www dir (to prevent file traversal).
     * @param fileName
     * @return
     * @throws IOException
     */
    private File getFileInWwwDir(String fileName) throws IOException {
        String requestedFilePath = new File(wwwDir, fileName).getCanonicalPath();
        if (requestedFilePath.startsWith(wwwDir.getCanonicalPath())) {
            return new File(requestedFilePath);
        }
        else {
            return null;
        }
    }

    String extractPathFromRequest(InputStream input) throws IOException {
        BufferedReader inputReader = new BufferedReader(new InputStreamReader(new LimitedInputStream(input, MAX_REQUEST_SIZE)));
        String line = inputReader.readLine();
        Matcher matcher = Pattern.compile("GET\\s+/?(\\S+)").matcher(line);
        if (matcher.matches()) {
            return matcher.group(1);
        }
        else {
            return null;
        }
    }
}
