![Kwik](https://bitbucket.org/pjtr/kwik/raw/master/docs/Logo%20Kwik%20rectangle.png)

## A QUIC client Java library

Kwik is a client implementation of the [QUIC](https://tools.ietf.org/html/draft-ietf-quic-transport-27) protocol in Java.

Kwik can be used to transport HTTP3, but it is not a HTTP3 client.
If you're looking for a HTTP3 client, check out [Flupke](https://bitbucket.org/pjtr/flupke).

Kwik is created an maintained by Peter Doornbosch. 

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
for details.

HTTP3 on top of Kwik is support by [Flupke, the Java HTTP3 client](https://bitbucket.org/pjtr/flupke).

Kwik supports IETF draft-27, the latest draft published by the IETF.

Implemented QUIC features:

* version negotation
* handshake based on TLS 1.3
* data exchange over bidirectional and unidirectional streams
* stateless retry
* session resumption (see -S and -R options)
* connection migration


## Usage

Build the client with gradle (`gradle build`)
and run the `kwik.sh` script or `java -jar build/libs/kwik.jar`. 

    usage: kwik <host>:<port> OR quic <host> <port> OR kwik http[s]://host:port
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
