# Kwik

## A QUIC client Java library

Kwik is an effort to implement a [QUIC](https://tools.ietf.org/html/draft-ietf-quic-transport-17) protocol client in Java.


## Not for production

Kwik is absolutely not suitable for any kind of production use. 
It does not implement the complete QUIC protocol and lacks important features that are necessary 
for a stable and reliable connection and for efficient use of network resources. 
Also it is not secure, as certificates are not validated. 
This project is for educational purposes only. 


## Status

The status of the project is proof of concept: it is possible to set up a connection with a QUIC server and exchange some data.
There is currently no retransmission at all, so a connection will fail if any network packet is dropped.

Kwik supports IETF draft-14, draft-15, draft-16 and draft-17.


## Usage

Build with gradle (`gradle build`)
and run the `quic.sh` script or `java -jar build/libs/quic.jar`. 

    usage: quic <host>:<port> OR quic <host> <port>
     -14                            use Quic version IETF_draft_14
     -15                            use Quic version IETF_draft_15
     -16                            use Quic version IETF_draft_16
     -17                            use Quic version IETF_draft_17
     -18                            use Quic version IETF_draft_18
     -c,--connectionTimeout <arg>   connection timeout in seconds
     -h,--help                      show help
     -l,--log <arg>                 logging options: [pdrsiSD]: (p)ackets
                                    received/sent, (d)ecrypted bytes, (r)aw bytes,
                                    (s)tats, (i)nfo, (S)ecrets, (D)ebug; default is
                                    "is", use (n)one to disable
                                
## Contact

If you have questions about this project, please mail the author (peter dot doornbosch) at luminis dot eu.

## License

This program is open source and licensed under LGPL (see the LICENSE.txt and LICENSE-LESSER.txt files in the distribution). 
This means that you can use this program for anything you like, and that you can embed it as a library in other applications, even commercial ones. 
If you do so, the author would appreciate if you include a reference to the original.
 
As of the LGPL license, all modifications and additions to the source code must be published as (L)GPL as well.
