![Kwik](https://bitbucket.org/pjtr/kwik/raw/master/docs/Logo%20Kwik%20rectangle.png)

## A QUIC client Java library

Kwik is a client implementation of the [QUIC](https://tools.ietf.org/html/draft-ietf-quic-transport-19) protocol in Java.


## Not for production

Kwik is absolutely not suitable for any kind of production use. 
It does not implement the complete QUIC protocol and lacks important features that are necessary 
for a stable and reliable connection and for efficient use of network resources. 
Also it is not secure, as certificates are not validated. 
For the time being, this project is for educational purposes only. 


## Status

The status of the project is proof of concept: it is possible to set up a connection with a QUIC server and exchange some data.
There is currently no retransmission at all, so a connection will fail if any network packet is dropped.

Kwik supports IETF draft-14, draft-15, draft-16, draft-17, draft-18 and draft-19.


## Usage

Build the client with gradle (`gradle build`)
and run the `quic.sh` script or `java -jar build/libs/quic.jar`. 

    usage: quic <host>:<port> OR quic <host> <port>
     -14                            use Quic version IETF_draft_14
     -15                            use Quic version IETF_draft_15
     -16                            use Quic version IETF_draft_16
     -17                            use Quic version IETF_draft_17
     -18                            use Quic version IETF_draft_18
     -19                            use Quic version IETF_draft_19
     -c,--connectionTimeout <arg>   connection timeout in seconds
     -h,--help                      show help
     -H,--http09 <arg>              send HTTP 0.9 request, arg is path, e.g.
                                    '/index.html'
     -k,--keepAlive <arg>           connection keep alive time in seconds
     -l,--log <arg>                 logging options: [pdrsiSD]: (p)ackets
                                    received/sent, (d)ecrypted bytes, (r)aw bytes,
                                    (s)tats, (i)nfo, (S)ecrets, (D)ebug; default is
                                    "is", use (n)one to disable
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
