![Kwik](https://bitbucket.org/pjtr/kwik/raw/master/docs/media/Logo_Kwik_rectangle.png)

## A QUIC implementation in Java

Kwik is an implementation of the [QUIC](https://en.wikipedia.org/wiki/QUIC) protocol in (100%) Java. 
Kwik started as client (library) only, but since May 2021 it supports both client and server.

**If you are upgrading from a version prior to 0.10, read the [CHANGELOG](https://github.com/ptrd/kwik/blob/master/CHANGELOG.md)
for upgrade instructions.**

QUIC is a brand-new transport protocol developed by the IETF, and is the transport layer for the (also new) HTTP3 protocol.
Although necessary for HTTP3, QUIC is more than just the transport protocol for HTTP3: most people consider QUIC as the 
"next generation TCP". It has similar properties as TCP, e.g. provide a reliable ordered stream, but is better in many ways:

* it can serve multiple streams (concurrently and sequential) over the same QUIC connection
* it does not suffer from the "head of line blocking" problem 
* it's encrypted and secured by TLS (not as a separate layer, but embedded in the protocol)
* it requires at most only one network roundtrip to setup the connection (the combination of TCP and TLS needs much more)

If you want to know more about QUIC and are able to understand the dutch language, check out
my [presentation on Luminis DevCon 2019](https://youtu.be/eR2tPOLQRws). 

If you're looking for a Java HTTP3 client or server, check out [Flupke](https://github.com/ptrd/flupke), which is built on top of Kwik.

Kwik is created and maintained by Peter Doornbosch. 
The latest greatest can always be found on [BitBucket](https://bitbucket.org/pjtr/kwik)
or [GitHub](https://github.com/ptrd/kwik).


## Status

Kwik implements all QUIC features, except that the server does not yet support connection migration (work in progress).
With respect to the interface Kwik offers to applications, it provides all necessary operations to exchange data, but
it does not support specifying stream priorities.
For both roles, interoperability is tested with a large number of other implementations, see [automated interoperability tests](https://interop.seemann.io/). 
Due to the fact that most implementations are still in active development, and that some test cases
(specifically testing behaviour in the context of packet loss and packet corruption) are non-deterministic, the results of the automatic
interoperability test vary with each run, but usually, Kwik is amongst the best w.r.t. the number of successful testcases.  

Kwik is still in active development, see [git history](https://github.com/ptrd/kwik/commits/master/). 

HTTP3 on top of Kwik is supported by [Flupke, the pure Java HTTP3 implementation](https://github.com/ptrd/flupke).

Kwik supports QUIC v1 ([RFC 9000](https://www.rfc-editor.org/rfc/rfc9000.html))
and QUIC v2 ([RFC 9369](https://www.rfc-editor.org/rfc/rfc9369.html)).


### Implemented QUIC features

* (QUIC v1) version negotiation
* handshake based on TLS 1.3
* data exchange over bidirectional and unidirectional streams
* stateless retry
* cipher suites TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384 and TLS_CHACHA20_POLY1305_SHA256
* key update
* session resumption
* 0-RTT
* Compatible Version Negotiation [RFC 9368](https://www.rfc-editor.org/rfc/rfc9368.html)
* QUIC V2 [RFC 9369](https://www.rfc-editor.org/rfc/rfc9369.html)
* Unreliable Datagram Extension [RFC 9221](https://www.rfc-editor.org/rfc/rfc9221.html)
  
Client only:

* connection migration (use the interactive mode of the sample client to try it)


### Is Kwik ready for production use?

It really depends on your use-case. 
First of all, as with all open source software, there is no guarantee the software will work, it is provided "as is".
Having said that, interoperability with other implementations is heavily tested and ok, so you can assume it works.
However, Kwik is not tested in various or extreme networking conditions, so your mileage may vary.  
As development focus has been on correctness and features (in that order), performance is not optimal yet.

Kwik does not yet implement all QUIC requirements. Specifically, it does not enable applications or application 
protocols to specify the relative priority of streams. Note that this will not introduce interoperability issues,
because the concept of priorities only exists in a peer; it does not affect the wire protocol. However, the division of
network capacity over streams cannot be influenced and might not even be fair (although in practice it probably will).
When wondering whether limitations would harm your use case: just go ahead and test it! When in doubt, you can 
always contact the author (see contact details below) for more information or help.


### Is Kwik secure?

The TLS library used by Kwik is also "home made". Although all security features are implemented (e.g. certificates are
checked as well as the Certificate Verify message that proofs possession of the certificate private key), and only
crypto algorithms provided by the JDK are used, it is not security tested nor reviewed by security experts. 
So if you plan to transfer sensitive data or are afraid of intelligence
services trying to spy on you, using Kwik is probably not the best idea.

## Usage

### Maven

[![Maven Central](https://img.shields.io/maven-central/v/tech.kwik/kwik.svg?label=Maven%20Central)](https://mvnrepository.com/artifact/tech.kwik/kwik)

Kwik is available in the Maven Central Repository. To use it in your project, add the following dependency to your pom.xml:

    <dependency>
        <groupId>tech.kwik</groupId>
        <artifactId>kwik</artifactId>
        <version>${kwik.version}</version>
    </dependency>

Check [Maven Central](https://central.sonatype.com/artifact/tech.kwik/kwik/versions) to find the version number of the latest greatest.

### Java Module System

The following Kwik artifacts define a Java module with the given name:
- kwik: `tech.kwik.core`
- kwik-h09: `tech.kwik.h09`
- kwik-qlog: `tech.kwik.qlog`
- kwik-samples: `tech.kwik.samples`

### Client

To connect to a QUIC server, first create a connection object with the builder, e.g.

    String applicationProtocolId = "....";
    QuicClientConnection connection = QuicClientConnection.newBuilder()
            .uri(URI.create("https://sample.com:443"))
            .applicationProtocol(applicationProtocolId)
            .build();

You need to provide the ALPN protocol ID of the application protocol that you want to run on top of QUIC (and that the
server you connect to supports). On the connection object simply call `connect()`:

    connection.connect();

Once connected, you can create a stream and start sending/receiving data, e.g.

    QuicStream quicStream = connection.createStream(true);
    OutputStream output = quicStream.getOutputStream();
    output.write(...)
    output.close();
    InputStream input = quicStream.getInputStream();
    input.read(...)
    
As QUIC servers generally limit the number of streams that clients can open concurrently, it is wise to close streams
when not used anymore. Kwik does this automatically when you `close()` the `OutputStream` and read *all* data from the
`InputStream`. If, for some reason, you do not read all data from the `InputStream`, call `QuicStream.abortReading()`
to free resources and let the server you know you abandoned the stream.

When, for example with local development, the server uses self-signed certificates, you need to disable certificate
checking. The builder has a method for this:

    builder.noServerCertificateCheck()

The builder has a lot more methods for configuring the connection, most of which are self-explanatory; see the [Builder interface in QuicClientConnection](https://github.com/ptrd/kwik/blob/master/core/src/main/java/tech/kwik/core/QuicClientConnection.java#L77).

The builder method `logger()` requires an implementation of the [Logger interface](https://github.com/ptrd/kwik/blob/master/core/src/main/java/tech/kwik/core/log/Logger.java); Kwik provides two convenient implementations
that you can use: `SysOutLogger` and `FileLogger`. Various log categories can be enabled or disabled by the 
`logXXX()` methods, e.g. `logger.logInfo(true)`.

Take a look at the samples in the [sample package](https://github.com/ptrd/kwik/tree/master/samples/src/main/java/tech/kwik/sample)
for more inspiration.

### Server

Creating a QUIC server with Kwik consist of a few steps. First you need to create an application protocol handler by
implementing the [ApplicationProtocolConnectionFactory](https://github.com/ptrd/kwik/blob/master/core/src/main/java/tech/kwik/core/server/ApplicationProtocolConnectionFactory.java) interface. Its `createConnection` method should return an implementation of [ApplicationProtocolConnection](https://github.com/ptrd/kwik/blob/master/core/src/main/java/tech/kwik/core/server/ApplicationProtocolConnection.java) that, as the name suggests,
represents your application protocol connection. It's `acceptPeerInitiatedStream` method is the handler that is called by 
Kwik when a client initiates a stream for the given protocol. The implementation of this `acceptPeerInitiatedStream` method
should start a stream handler, but should itself return immediately, as it is called on the thread that handles
incoming QUIC messages. If, for example, your application protocol follows the request-response model, the stream handler
reads the request from the QUIC stream, processes it, creates a response, writes the response to the QUIC stream and closes the stream.

To complete the `ApplicationProtocolConnectionFactory` you should at least override the following two methods of the
[ApplicationProtocolSettings](https://github.com/ptrd/kwik/blob/master/core/src/main/java/tech/kwik/core/server/ApplicationProtocolSettings.java) 
interface:

    int maxConcurrentPeerInitiatedUnidirectionalStreams()
    int maxConcurrentPeerInitiatedBidirectionalStreams()

These methods communicate to Kwik how many (concurrent) streams the protocol needs. In most cases, these methods return either 0 or Long.MAX_VALUE,
to indicate that unidirectional or bidirectional streams are used (Long.MAX_VALUE) or are not used (value 0) by the application protocol.
Some protocols define an exact number of unidirectional streams to be used as control stream, for example HTTP/3 needs 3 unidirectional streams, no more, no less.
In such cases, the `maxConcurrentUnidirectionalStreams` method should return the exact number.

Once you have a proper implementations of `ApplicationProtocolConnectionFactory` and `ApplicationProtocolConnection`, 
you can create a `ServerConnector` and register the `ApplicationProtocolConnectionFactory`. The `ServerConnector` listens 
for new connections on a given port and handles them according to protocols that are registered on it. 

The `ServerConnector` needs a server certificate and the corresponding private key for authentication. The preferred way
to provide these, is via a Java `KeyStore` object. However, if your server certificate is of type RSA you can still use the
(now deprecated) method that takes `FileInputStream`'s for both the certificate and the private key.

It is not possible to create a Java KeyStore directly from a certificate file in PEM format, but there is a work-around
using a .p12. For example, if your certificate is stored in PEM format in `cert.pem` and its corresponding private key in
'key.pem', you can create a Java KeyStore file with

    openssl pkcs12 -export -clcerts -in cert.pem -inkey key.pem -name servercert -out cert.p12
    keytool -keystore cert.jks -importkeystore -srckeystore cert.p12 -srcstoretype PKCS12 -deststorepass secret -srcstorepass secret

resulting in a KeyStore file named 'cert.jks', containing the given server certificate with alias `servercert` and `secret` 
as the value for both the container and the key password.

To create a `ServerConnector`, use the builder, e.g.

    ServerConnector serverConnector = ServerConnector.builder()
            .withPort(443)
            .withKeyStore(keyStore, "servercert", "secret".toCharArray())
            .withConfiguration(serverConnectionConfig)
            .withLogger(log)
            .build(); 

register your protocol handler:

    serverConnector.registerApplicationProtocol("myapplicationprotocol", new MyApplicationProtocolConnectionFactory);

and start the connector:

    serverConnector.start();

The `serverConnectionConfig` that is needed by the `ServerConnector.Builder` defines the configuration for your server. 
For most settings you can get away with the defaults, except for one thing: you need to specify how many streams
the client is allowed to have open *concurrently* in one QUIC connection. A larger value means your client(s) can
do more work in parallel, but also can claim more resources. So `infinite` would be a bad choice, as that would make your
server an easy victim for a denial of service attack. Furthermore: only allow the type of stream (unidirectional or bidirectional)
that you actually support in the application protocol handler; again, if you fail to do so, you give attackers a change
to claim resources that are not used. For example, if your application protocol does not use unidirectional streams, 
just don't set `maxOpenUnidirectionalStreams` as the default is 0, and provide a valid value for bidirectional streams, e.g.

    ServerConnectionConfig.builder()
            .maxOpenPeerInitiatedBidirectionalStreams(50)  // Mandatory setting to maximize concurrent streams on a connection.
            .build();

That concludes creating a server. You can find working examples in the
[sample directory](https://github.com/ptrd/kwik/tree/master/samples/src/main/java/tech/kwik/sample).



### Development

To build the project:

- clone the git repository and cd into the directory
- build with gradle wrapper: `./gradlew build` (or `gradlew.bat build` on Windows).

Gradle will write the output to each submodule's `build/libs` directory, e.g. the core library can be found
in `core/build/libs`.

To use IntelliJ for development, either just open the project directory in IntelliJ and it will pick up the gradle file,
or generate IntelliJ project files with `gradle idea` and open the generated kwik.ipr file. The second option will
give a better developer experience.


### Sample Client

Kwik also provides a command line client that can be used to experiment with the QUIC protocol and
even provides an interactive shell for more QUIC fun.

To run the sample client, execute the `kwik.sh` script,
or unzip the cli distribution file in `cli/build/distributions/kwik-cli-*.zip` and run `kwik-cli` or `kwik-cli.bat`.
In the latter case, the client will not support HTTP/3, as the run script in the distribution does not have `flupke.jar`
on the classpath (but of course you can modify to script to add that).
You can also run the client with `gradle run` (after `cd`-ing to the `cli` directory), but than you have to pass
the command line args for the Kwik cli as `--args='-T -H /index.html example.com 4433'`. This option also lacks HTTP/3 support.

Usage of the sample client:

    kwik <host>:<port> OR quic <host> <port> OR kwik http[s]://host:port
     -A,--alpn <arg>                set alpn (default is hq-xx)
        --aes128gcm                 use AEAD_AES_128_GCM cipher suite
        --aes256gcm                 use AEAD_AES_256_GCM cipher suite
     -c,--connectionTimeout <arg>   connection timeout in seconds
        --chacha20                  use ChaCha20 as only cipher suite     
        --clientCertificate <arg>   certificate (file) for client
                                    authentication
        --clientKey <arg>           private key (file) for client certificate
     -h,--help                      show help
     -H,--http <arg>                send HTTP GET request, arg is path, e.g.
                                    '/index.html'
     -i,--interactive               start interactive shell
        --initialRtt <arg>          custom initial RTT value (default is 500)
     -k,--keepAlive <arg>           connection keep alive time in seconds
     -l,--log <arg>                 logging options: [pdrcsiRSD]: (p)ackets
                                    received/sent, (d)ecrypted bytes, (r)ecovery,
                                    (c)ongestion control, (s)tats, (i)nfo, (R)aw
                                    bytes, (S)ecrets, (D)ebug; default is "ip", use
                                    (n)one to disable
     -L,--logFile <arg>             file to write log message too
        --noCertificateCheck        do not check server certificate
     -O,--output <arg>              write server response to file
     -R,--resumption key <arg>      session ticket file
        --reservedVersion           use reserved version to trigger version
     -S,--storeTickets <arg>        basename of file to store new session tickets
        --saveServerCertificates <arg>   store server certificates in given file
        --secrets <arg>             write secrets to file (Wireshark format)
     -T,--relativeTime              log with time (in seconds) since first packet 
     -v,--version                   show Kwik version
     -v1                            use Quic version 1           
     -v1v2                          use Quic version 1, request version 2
     -v2                            use Quic version 2
     -Z,--use0RTT                   use 0-RTT if possible (requires -H and -R)
            
If you do not provide the `--http` or the `--keepAlive` option, the Quic connection will be closed immediately after setup.

Plain Kwik will use HTTP 0.9 for http requests. However, if the flupke.jar is on the classpath (when using
the kwik.sh script, it will try to load the plugin from the `libs` directory), it will use Flupke HTTP3 client for the
HTTP request.

### Sample Server

To run the demo web server, execute `tech.kwik.sample.SampleWebServer` with the following arguments:
- certificate file
- private key file
- port number
- www directory to serve
or
- keystore file containing (only) the server certificate and key
- keystore password (which should match the key password)
- port number
- www directory to serve

This will start the server in retry-mode (see https://www.rfc-editor.org/rfc/rfc9000.html#name-address-validation-using-re).
To run without retry-mode, add the `--noRetry` flag as first argument.


## Adding HTTP/3 Support to Kwik client or server.

A plain Kwik client or server will only provide "HTTP/0.9", which is a very simplified form of HTTP/1, which the QUIC implementors
have been using for early testing. 

To add HTTP/3 to Kwik you should use the flupke plugin `flupke.jar`, which you can download 
from [Maven](https://search.maven.org/artifact/tech.kwik/flupke), and add it to the run classpath.
                                
## Contact

If you have questions about this project, please mail the author (peter dot doornbosch) at luminis dot eu.

## Acknowledgements

Thanks to Piet van Dongen for creating the marvellous logo!

## License

This program is open source and licensed under LGPL (see the LICENSE.txt and LICENSE-LESSER.txt files in the distribution). 
This means that you can use this program for anything you like, and that you can embed it as a library in other applications, even commercial ones. 
If you do so, the author would appreciate if you include a reference to the original.
 
As of the LGPL license, all modifications and additions to the source code must be published as (L)GPL as well.

If you want to use the source with a different open source license, contact the author.
