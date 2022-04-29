NFSC multiplayer UDP packet decryptor. Decrypts packets in the provided pcapng file.

The needed encryption key is in a `EGEG` FESL packet sent to the theater server.
* For decrypting packets sent to/received from `I:P`:  
`./mpdecrypt in.pcapng out.pcapng <EKEY> <P>`
* For decrypting packets sent to/received from `INT-IP:INT-PORT`:  
`./mpdecrypt in.pcapng out.pcapng <EKEY> int:<INT-PORT>`
