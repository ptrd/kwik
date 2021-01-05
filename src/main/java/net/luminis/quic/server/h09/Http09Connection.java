/*
 * Copyright © 2020 Peter Doornbosch
 *
 * This file is part of Kwik, a QUIC client Java library
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
package net.luminis.quic.server.h09;

import net.luminis.quic.QuicConnection;
import net.luminis.quic.Version;
import net.luminis.quic.run.KwikCli;
import net.luminis.quic.server.ApplicationProtocolConnection;
import net.luminis.quic.stream.QuicStream;

import java.io.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Http09Connection extends ApplicationProtocolConnection implements Consumer<QuicStream> {

    private static AtomicInteger threadCount = new AtomicInteger();

    private File wwwDir;

    public Http09Connection(QuicConnection quicConnection, File wwwDir) {
        this.wwwDir = wwwDir;
        quicConnection.setPeerInitiatedStreamCallback(this);
    }

    @Override
    public void accept(QuicStream quicStream) {
        Thread thread = new Thread(() -> handleRequest(quicStream));
        thread.setName("http-" + threadCount.getAndIncrement());
        thread.start();
    }

    void handleRequest(QuicStream quicStream) {
        try {
            String fileName = extractPathFromRequest(quicStream.getInputStream());
            if (fileName != null) {
                File file = getFileInWwwDir(fileName);
                OutputStream outputStream = quicStream.getOutputStream();
                if (file != null && file.exists() && file.isFile() && file.canRead()) {
                    FileInputStream fileInputStream = new FileInputStream(file);
                    fileInputStream.transferTo(outputStream);
                    fileInputStream.close();
                }
                else if (fileName.equals("version") || fileName.equals("version.txt")) {
                    OutputStreamWriter outputStreamWriter = new OutputStreamWriter(outputStream);
                    outputStreamWriter.write("Kwik version/build number: " + KwikCli.getVersion() + "\n");
                    outputStreamWriter.close();
                }
                else {
                    OutputStreamWriter outputStreamWriter = new OutputStreamWriter(outputStream);
                    outputStreamWriter.write("404: file '" + fileName + "' not found\n");
                    outputStreamWriter.close();
                }
                outputStream.flush();
                outputStream.close();
            }
            else {
                System.out.println("Error: cannot extract file name");
            }
        } catch (IOException e) {
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
        BufferedReader inputReader = new BufferedReader(new InputStreamReader(input));
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
