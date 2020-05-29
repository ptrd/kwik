![Kwik](https://bitbucket.org/pjtr/kwik/raw/master/docs/Logo%20Kwik%20rectangle.png)

## A QUIC client Java library

Kwik is a client implementation of the [QUIC](https://en.wikipedia.org/wiki/QUIC) protocol in Java.

QUIC is a brand new transport protocol developed by the IETF, which will be the transport layer for the also new HTTP3 protocol.
Although necessary for HTTP3, QUIC is more than just the transport protocol for HTTP3: most people consider QUIC as the 
"next generation TCP". It has similar properties as TCP, e.g. provide a reliable ordered stream, but is better in many ways:

* it can serve multiple streams (concurrently and sequential) over the same QUIC connection
* it does not suffer from the "head of line blocking" problem 
* it's encrypted and secured by TLS (not as a separate layer, but embedded in the protocol)
* it requires at most only one network roundtrip to setup the connection (the combination of TCP and TLS needs much more)

If you want to know more about QUIC and are able to understand the dutch language, check out
my [presentation on Luminis DevCon 2019](https://youtu.be/eR2tPOLQRws). 

If you're looking for a Java HTTP3 client, check out [Flupke](https://bitbucket.org/pjtr/flupke), which is build on top of Kwik.

Kwik is created an maintained by Peter Doornbosch. The latest greatest can always be found on [BitBucket](https://bitbucket.org/pjtr/kwik).

## Not for production

Kwik is not yet suitable for production use. 
Apart from the fact that the QUIC specification is still work in progress by the IETF, Kwik does not yet implement 
the complete (draft) specification. 
Important features like congestion control are implemented but not yet extensively tested. 
Also, a secure connection is not guaranteed, as server certificates are not yet validated.
Use at your own risk.
And apart from that: have fun!

## Status

The status of the project is that most QUIC features are implemented. Interoperability is tested with a large
number of server implementations, see the [automated interoperability tests](https://interop.seemann.io/) and 
the [QUIC interop matrix](https://docs.google.com/spreadsheets/d/1D0tW89vOoaScs3IY9RGC0UesWGAwE6xyLk0l4JtvTVg/edit)
for details. Due the to fact that all (server) implementations are still in active development, and that some test cases
(testing behaviour due to packet loss and packet corruption) are non-deterministic, the results of the automatic
interoperability test vary with each run, but usually, Kwik is amongst the best clients w.r.t. the number of  
successful testcases.  
Kwik is still in active development, see [git history](https://bitbucket.org/pjtr/kwik/commits/). 

HTTP3 on top of Kwik is supported by [Flupke, the Java HTTP3 client](https://bitbucket.org/pjtr/flupke).

Kwik supports IETF draft-28, the latest draft published by the IETF.

Implemented QUIC features:

* version negotation
* handshake based on TLS 1.3
* data exchange over bidirectional and unidirectional streams
* stateless retry
* session resumption (see -S and -R options of the sample client)
* connection migration (use the interactive mode of the sample client to try it)
* 0-RTT
* cipher suites TLS_AES_128_GCM_SHA256 and TLS_CHACHA20_POLY1305_SHA256


## Usage

Kwik is both a library that can be used in any Java application to setup and use a QUIC connection, 
and a (sample) command line client that can be used to experiment with the QUIC protocol. 
If you want to use Kwik as a library, consider the various classes in 
the [run package](https://bitbucket.org/pjtr/kwik/src/master/src/main/java/net/luminis/quic/run/) as samples
of how to setup and use a QUIC connection with Kwik in Java.

To build the client/library, run gradle (`gradle build`).
To run the sample client, execute the `kwik.sh` script or `java -jar build/libs/kwik.jar`. 

Usage of the sample client:

    kwik <host>:<port> OR quic <host> <port> OR kwik http[s]://host:port
     -A,--alpn <arg>                set alpn (default is hq-xx)
     -c,--connectionTimeout <arg>   connection timeout in seconds
     -h,--help                      show help
     -H,--http09 <arg>              send HTTP 0.9 request, arg is path, e.g.
                                    '/index.html'
     -i,--interactive               start interactive shell
     -k,--keepAlive <arg>           connection keep alive time in seconds
     -l,--log <arg>                 logging options: [pdrcsiRSD]: (p)ackets
                                    received/sent, (d)ecrypted bytes, (r)ecovery,
                                    (c)ongestion control, (s)tats, (i)nfo, (R)aw
                                    bytes, (S)ecrets, (D)ebug; default is "ip", use
                                    (n)one to disable
     -L,--logFile <arg>             file to write log message too
     -O,--output <arg>              write server response to file
     -R,--resumption key <arg>      session ticket file
        --reservedVersion           use reserved version to trigger version
     -S,--storeTickets <arg>        basename of file to store new session tickets
        --secrets <arg>             write secrets to file (Wireshark format)
     -T,--relativeTime              log with time (in seconds) since first packet                                    
     -Z,--use0RTT                   use 0-RTT if possible (requires -H and -R)
            
If you do not provide the `--http09` or the `--keepAlive` option, the Quic connection will be closed immediately after setup.

                                
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