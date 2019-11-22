![Kwik](https://bitbucket.org/pjtr/kwik/raw/master/docs/Logo%20Kwik%20rectangle.png)

## A QUIC client Java library

Kwik is a client implementation of the [QUIC](https://tools.ietf.org/html/draft-ietf-quic-transport-19) protocol in Java.

Kwik can be used to transport HTTP3, but it is not a HTTP3 client.
If you're looking for a HTTP3 client, check out [Flupke](https://bitbucket.org/pjtr/flupke).
 

## Not for production

Kwik is not yet suitable for production use. 
Apart from the fact that the QUIC specification is still work in progress by the IETF, Kwik does not yet implement 
the complete (draft) specification. 
It lacks important features that are necessary for a stable and reliable connection and for efficient use of network
resources. For example, congestion control is not yet implemented. 
Also it is not secure, as server certificates are not yet validated. 
For the time being, this project is for educational purposes only. 


## Status

The status of the project is proof of concept: it is possible to set up a connection with a QUIC server and exchange
data. See [Flupke](https://bitbucket.org/pjtr/flupke) for a sample HTTP3 client.

Kwik supports IETF draft-20, draft-22 and draft-23.

Implemented QUIC features:

* version negotation
* stateless retry
* session resumption (see -S and -R options)

## Usage

Build the client with gradle (`gradle build`)
and run the `kwik.sh` script or `java -jar build/libs/kwik.jar`. 

    usage: kwik <host>:<port> OR quic <host> <port>
     -20                            use Quic version IETF_draft_20
     -22                            use Quic version IETF_draft_22
     -23                            use Quic version IETF_draft_23
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
     -S,--storeTickets <arg>        basename of file to store new session tickets
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
