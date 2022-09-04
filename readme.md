![Kwik](https://bitbucket.org/pjtr/kwik/raw/master/docs/media/Logo_Kwik_rectangle.png)

## A QUIC implementation in Java

Kwik is an implementation of the [QUIC](https://en.wikipedia.org/wiki/QUIC) protocol in (100%) Java. 
Kwik started as client (library) only, but since May 2021 it supports both client and server.

QUIC is a brand-new transport protocol developed by the IETF, which will be the transport layer for the also new HTTP3 protocol.
Although necessary for HTTP3, QUIC is more than just the transport protocol for HTTP3: most people consider QUIC as the 
"next generation TCP". It has similar properties as TCP, e.g. provide a reliable ordered stream, but is better in many ways:

* it can serve multiple streams (concurrently and sequential) over the same QUIC connection
* it does not suffer from the "head of line blocking" problem 
* it's encrypted and secured by TLS (not as a separate layer, but embedded in the protocol)
* it requires at most only one network roundtrip to setup the connection (the combination of TCP and TLS needs much more)

If you want to know more about QUIC and are able to understand the dutch language, check out
my [presentation on Luminis DevCon 2019](https://youtu.be/eR2tPOLQRws). 

If you're looking for a Java HTTP3 client or server, check out [Flupke](https://bitbucket.org/pjtr/flupke), which is built on top of Kwik.

Kwik is created and maintained by Peter Doornbosch. The latest greatest can always be found on [BitBucket](https://bitbucket.org/pjtr/kwik).


## Status

Kwik implements all QUIC features, except that the server does not yet support connection migration.
With respect to the interface Kwik offers to applications, it provides all necessary operations to exchange data, but
it does not support specifying stream priorities.
For both roles, interoperability is tested with a large number of other implementations, see [automated interoperability tests](https://interop.seemann.io/). 
Due the to fact that most implementations are still in active development, and that some test cases
(specifically testing behaviour in the context of packet loss and packet corruption) are non-deterministic, the results of the automatic
interoperability test vary with each run, but usually, Kwik is amongst the best w.r.t. the number of successful testcases.  

Kwik is still in active development, see [git history](https://bitbucket.org/pjtr/kwik/commits/). 

HTTP3 on top of Kwik is supported by [Flupke, the Java HTTP3 client](https://bitbucket.org/pjtr/flupke).

Kwik supports QUIC v1 ([RFC 9000](https://www.rfc-editor.org/rfc/rfc9000.html))
and QUIC v2 ([draft-ietf-quic-v2-05](https://www.ietf.org/archive/id/draft-ietf-quic-v2-05.html))
as well as a few older IETF drafts: 
[draft-32](https://tools.ietf.org/html/draft-ietf-quic-transport-32),
[draft-31](https://tools.ietf.org/html/draft-ietf-quic-transport-31),
[draft-30](https://tools.ietf.org/html/draft-ietf-quic-transport-30), and
[draft-29](https://tools.ietf.org/html/draft-ietf-quic-transport-29).


### Implemented QUIC features

* (QUIC v1) version negotiation
* handshake based on TLS 1.3
* data exchange over bidirectional and unidirectional streams
* stateless retry
* cipher suites TLS_AES_128_GCM_SHA256 and TLS_CHACHA20_POLY1305_SHA256
* key update
* session resumption
* 0-RTT
* compatible version negotiation [draft-ietf-quic-version-negotiation-09](https://www.ietf.org/archive/id/draft-ietf-quic-version-negotiation-09.html)
  
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

### Building

To build the project:

- clone the git repository and cd into the directory
- update / get the agent15 (TLS 1.3 library) sources by executing `git submodule update --init --recursive`
- build with gradle wrapper: `./gradlew build` (or `gradlew.bat build` on Windows).

Gradle will write the output to `build/libs`.

### Client

Kwik is both a library that can be used in any Java application to set up and use a QUIC connection, 
and a (sample) command line client that can be used to experiment with the QUIC protocol. 
If you want to use Kwik as a library, consider the various classes in 
the [run package](https://bitbucket.org/pjtr/kwik/src/master/src/main/java/net/luminis/quic/run/) as samples
of how to setup and use a QUIC connection with Kwik in Java.

To run the sample client, execute the `kwik.sh` script or `java -jar build/libs/kwik.jar`. 

Usage of the sample client:

    kwik <host>:<port> OR quic <host> <port> OR kwik http[s]://host:port
     -29                            use Quic version IETF_draft_29
     -30                            use Quic version IETF_draft_30
     -31                            use Quic version IETF_draft_31
     -32                            use Quic version IETF_draft_32    
     -A,--alpn <arg>                set alpn (default is hq-xx)
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
     -Z,--use0RTT                   use 0-RTT if possible (requires -H and -R)
            
If you do not provide the `--http` or the `--keepAlive` option, the Quic connection will be closed immediately after setup.

Plain Kwik will use HTTP 0.9 for http requests. However, if the flupke-plugin.jar is on the classpath (when using
the kwik.sh script, it will try to load the plugin from the `libs` directory), it will use Flupke HTTP3 client for the
HTTP request.

### Server

To run the demo web server, execute `java -cp kwik.jar net.luminis.quic.run.SampleWebServer` with the following arguments:
- certificate file
- private key file
- port number
- www directory to serve

This will start the server in retry-mode (see https://quicwg.org/base-drafts/rfc9000.html#name-address-validation-using-re).
To run without retry-mode, add the `--noRetry` flag as first argument.  


## Adding HTTP/3 Support to Kwik client or server.

A plain Kwik client or server will only provide "HTTP/0.9", which is a very simplified form of HTTP/1, which the QUIC implementors
have been using for early testing. 

To add HTTP/3 to Kwik you should use the flupke-plugin:
- Clone the repo [Flupke](https://bitbucket.org/pjtr/flupke) and cd into its directory.
- Build with `gradle flupkePlugin`
- Add the generated flupke-plugin.jar (in build/libs) to the client or server classpath, e.g. for the server run `java -cp kwik.jar:flupke-plugin.jar net.luminis.quic.run.SampleWebServer`. 
                                
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