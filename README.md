Nostr Wallet Connect ([NIP-47](https://github.com/nostr-protocol/nips/blob/master/47.md)) is an open protocol enabling applications to interact with bitcoin lightning wallets. 

nwc-notification-idotmatrix watches for NIP-47 notification events (payments received and sent). Events are decrypted and pushed to an iDotMatrix pixel screen (via [this fork of pixelart-tracker](https://github.com/enlunder/pixelart-tracker)). 

Note: you need to run pixelart-tracker as a separate process, perhaps on a Raspberry Pi Zero close to the iDotMatrix screen? 

#### Usage:

Before launching notification-watcher you need to set the NWC environment variable to the connection string of your wallet service and the IDOTMATRIX environment variable to the address listened to by pixelart-tracker.

```
export NWC="nostr+walletconnect://..."
export IDOTMATRIX="http://.../message"
python notification-watcher.py
```

