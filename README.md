Nostr Wallet Connect ([NIP-47](https://github.com/nostr-protocol/nips/blob/master/47.md)) is an open protocol enabling applications to interact with bitcoin lightning wallets. 

nwc-notification-idotmatrix watches for NIP-47 notification events (payments received and sent) as well as Lightning Zap ([NIP-57](https://github.com/nostr-protocol/nips/blob/master/57.md)) receipts. The NWC events are decrypted and pushed to an iDotMatrix pixel screen (via [this fork of pixelart-tracker](https://github.com/enlunder/pixelart-tracker)). 

Note: you need to run pixelart-tracker as a separate process, perhaps on a Raspberry Pi Zero close to the iDotMatrix screen? 

#### Usage:

Before launching notification-watcher you need to set the NWC environment variable to the connection string of your wallet service, the IDOTMATRIX environment variable to the address listened to by pixelart-tracker. If you wish to monitor for Zaps, include the associated npubs in a PUBKEYS enviroment variable, separated by commas. Relays can be specified similarly in a RELAY variable.

```
export NWC="nostr+walletconnect://..."
export IDOTMATRIX="http://.../message"
export PUBKEYS="npub1...,npub2..."
export RELAYS="wss://relay.damus.io"
python notification-watcher.py

```


