# Brainvault, command line bitcoin wallet

Brainvault is a simple command-line based Bitcoin wallet that runs from the terminal.
It is fully determinic, meaning that it operates by using an initial seed 
(passphrase) in order to generate priv/pub keypairs. Note that this is not 
a BIP32 wallet - it uses SHA256 to hash the seed, because it aims to provide a 
simple way to rederive private keys in situations where only simple cryptographic 
primitives such as SHA256 are available (every Linux system).

### General features

* Completely command line based
* No dependencies and no installation, works on any system with Python 2.7
* Keys are derived deterministically from a passphrase/seed 
* Keys are never saved anywhere - the wallet state is completely ephemeral and operates
in RAM (unless chosen otherwise)
* Does not download the block chain - it uses external block explorer 
APIs to fetch balance and UTXO data (supports BlockchainInfo, Blockr, BlockCypher 
and any instance of Insight)
* If you ever lose access to this software, your keys can be manually rederived 
using the standard brainwallet mechanism (see [this section](#key-derivation-algorithms) for details).
* Randomizes and obfuscates the order of outputs in a transaction 
* Crafts and signs transactions locally - your keys never leave the memory of your computer
* All API calls are sent via TLS/SSL so your transactions cannot be recorded via MITM attacks

### Example usage

```
pi@raspberrypi ~/brainvault $ ./brainvault.py
Data provider: BlockchainInfo, host: https://blockchain.info
Seed:
Deriving keys: [||||||||||||||||||||] 100% Done...

Used addressess with a balance of zero BTC are hidden.
Use list -s to show such addresses.

#       address                                 USD             BTC
0       186fDwcZRpgd5mKZMRdQmSqe5PiW5JZKCw      725.57          1.0988
1       127cxwu1QbW2ErqK7b87yvSHXt7tWdyYij      3492.18         5.316
2       1GCeWfXF1ahguPpYTFjKWYHpgTmaC8zn2e      N/A             Unused address
3       1Pus6Xhy4Fg6p6e4aEikReM5snBmgu54Ud      N/A             Unused address
4       1Fv1gDNV8JMBW7X1sQAd1GiwTCK3Cw9DYQ      N/A             Unused address
------------------------------------------------------------------------
TOTAL:                                          4217.75         6.4148

Type 'help' to display available commands
> send 0 1BTCorgHwCg6u2YSAWKgS17qUad6kHmtQW 0.3

From:   186fDwcZRpgd5mKZMRdQmSqe5PiW5JZKCw [0]
To:     0.3 -> 1BTCorgHwCg6u2YSAWKgS17qUad6kHmtQW
Change: 0.7987 -> 1GCeWfXF1ahguPpYTFjKWYHpgTmaC8zn2e [2]
Fee:    0.0001 BTC
Proceed? (y/n)y
Transaction pushed.
txhash: 7ddc84b605d3df6e7e335ace19ab4fde3d042e50fa8204954b8c8bd203c0a5b7
> exit
```

### General usage

To see the available startup options, run the wallet with `-h`. Once the wallet is running, type `help` to list the available commands. Every command can be run with the `-h` option in order to display help.

Initially, all addresses with a non-zero balance are displayed. The cutoff (gap limit) for unused addresses is 5 in order to save space. Already used addresses with a balance of 0 are hidden in order to discourage address reuse, but can still be displayed with `list -s`. To display a specific number of generated addresses, use `list -u [N]`.

To generate a specific range of addresses, run the program with `-r [N-M]` for a N to M range, or `-r [N]` for the first N addresses starting from 0.

The wallet can be run with a number of different data providers (block explorer APIs). In order to change the data provider, run the wallet with `-d` or `--dataProvider`. Some block explorers are open source and have the same interface/operation contract and API methods but exist on different hosts. In order to specify a different host for the chosen data provider, specify the `-u` or `--url` parameter. 

When sending funds, the first unused address is used for change. If there are no unused addresses, change will be sent back to the sending address.

### Key derivation algorithms

Brainvault can be run with the following key derivation algorithms:

* Single brainwallet (run with `-a 0`)
* [Type 1 deterministic wallet](https://en.bitcoin.it/wiki/Deterministic_wallet#Type_1_deterministic_wallet) (default mode, or run with `-a 1` explicitly). This algorithm appends numbers from 0 to n to the initial passphrase/seed and uses the resulting strings as seeds for private keys. The default number of generated addresses is 25. Example: using the phrase `correct horse battery staple`, the fourth key in the sequence will be derived from the string `correct horse battery staple3`.

It is trivial to derive your private keys on any Linux system without using this wallet. Simply run your passphrase string with the desired address index appended to it through SHA256, and the resulting hex string is your private key exponent.

```bash
$ echo -n "correct horse battery staple3" | sha256sum
39ca62fd663f7106da291666f916baf93076a59046004f4dc4eaf4d5085d9f6b  -
```

### Credits
The wallet uses Vitalik Buterin's pybitcointools project for elliptic curve 
operations and transaction signing.

