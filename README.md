# bitgod
Drop-in replacement for bitcoind JSON-RPC which proxies to the BitGo API
=========

# Summary
BitGoD is a NodeJS package and binary which operates a bitcoind-compatible JSON-RPC API.  It is designed to proxy non-wallet API calls to a local bitcoind
instance, though this is not required, if those API calls are not used. For wallet-related API calls, BitGoD speaks on the back-end to the
[BitGo REST API](https://www.bitgo.com/api), and allows the client to easily operate a multi-sig wallet as if it were dealing with a standard bitcoind instance.

[![Known Vulnerabilities](https://snyk.io/test/npm/bitgod/badge.svg)](https://snyk.io/test/npm/bitgod)

# Installation

**NodeJS must be installed as a prerequisite.**
```
$ npm install -g bitgod
```

# Running

Running **bitgod -h** will produce usage information.

```
$ bitgod -h
usage: bitgod [-h] [-v] [-conf CONF] [-env ENV] [-rpcbind RPCBIND]
              [-rpcport RPCPORT] [-rpcuser RPCUSER] [-rpcpassword RPCPASSWORD]
              [-rpcssl] [-rpcsslkey RPCSSLKEY] [-rpcsslcert RPCSSLCERT]
              [-proxyhost PROXYHOST] [-proxyport PROXYPORT]
              [-proxyuser PROXYUSER] [-proxypassword PROXYPASSWORD]
              [-proxyrpcssl] [-proxyrpcsslallowunauthorizedcerts]
              [-proxy PROXY] [-masqueradeaccount MASQUERADEACCOUNT]
              [-validate {loose,strict}]


BitGoD

Optional arguments:
  -h, --help            Show this help message and exit.
  -v, --version         Show program's version number and exit.
  -conf CONF            Specify configuration file (default: /etc/bitgod.conf)
  -env ENV              BitGo environment to use [prod test (default)]
  -rpcbind RPCBIND      Bind to given address to listen for JSON-RPC
                        connections (default: localhost)
  -rpcport RPCPORT      Listen for JSON-RPC connections on RPCPORT (default:
                        9332 or testnet: 19332)
  -rpcuser RPCUSER      Username for RPC basic auth (default: none)
  -rpcpassword RPCPASSWORD
                        Password for RPC basic auth (default: none)
  -rpcssl               Listen using JSON RPC with SSL
  -rpcsslkey RPCSSLKEY  Path to SSL Key when listening with SSL is on
  -rpcsslcert RPCSSLCERT
                        Path to SSL Cert when listening with SSL is on
  -proxyhost PROXYHOST  Host for proxied bitcoind JSON-RPC (default:
                        localhost)
  -proxyport PROXYPORT  Port for proxied bitcoind JSON-RPC (default: 8332 or
                        testnet: 18332)
  -proxyuser PROXYUSER  Username for proxied bitcoind JSON-RPC (default:
                        bitcoinrpc)
  -proxypassword PROXYPASSWORD
                        Password for proxied bitcoind JSON-RPC
  -proxyrpcssl          Use SSL when connecting to proxied bitcoind JSON-RPC
  -proxyrpcsslallowunauthorizedcerts
                        Allow SSL certs which are self-signed
  -proxy PROXY          Proxy to bitcoind JSON-RPC backend for non-wallet
                        commands
  -masqueradeaccount MASQUERADEACCOUNT
                        Ignore wallet account values and masquerade
                        transactions as being in this account
  -validate {loose,strict}
                        Validate transaction data against local bitcoind
                        (requires -proxy)
```

Running BitGoD with no command line args should start the server, using BitGo's test environment at [test.bitgo.com](https://test.bitgo.com/).

```
$ bitgod
JSON-RPC server active on localhost:19332
```

To interact with BitGoD, you use the *bitcoin-cli* command that is normally used to interact with bitcoind. For example:

```
$  bitcoin-cli -rpcport=19332 getinfo
{
    "bitgod" : true,
    "version" : "0.2.0",
    "testnet" : true,
    "token" : false,
    "wallet" : false,
    "keychain" : false,
    "paytxfee" : 0.00010000
}
```

# Establishing a Session

BitGoD is designed to serve as an interface for a single wallet on a single BitGo user account at one time. In order to establish a BitGo session for BitGoD, you need to pass it an access token. You can easily get a normal short-lived access token by logging into the test environment with the [BitGo Command-Line Tool](https://github.com/BitGo/bitgo-cli), and running:

```
$ bitgo token
386e5cc16bcfedc6865ee7e7522d0b21361ca98da2635917f56b148076488509
```

```
$ bitcoin-cli -rpcport=19332 settoken 386e5cc16bcfedc6865ee7e7522d0b21361ca98da2635917f56b148076488509
Authenticated as BitGo user: user@domain.com
```

To do much of anything useful, you will also need to tell BitGoD which wallet you want to use:

```
$ bitcoin-cli -rpcport=19332 setwallet 2N6d5SYvu1xQeSQnpZ4VNVZ6TcRYcqkocao
Set wallet: 2N6d5SYvu1xQeSQnpZ4VNVZ6TcRYcqkocao
```

In order to transact, you will need to use either the **walletpassphrase** command or the **setkeychain** command. The semantics
of **walletpassphrase** are identical to those in bitcoind. Setting the passphrase causes BitGoD to download the encrypted user
keychain from BitGo and try to decrypt it. If the passphrase validates, it is kept in memory for the specified time period.
Note, that if you do not have an unlocked long-term session token, you will first have to unlock the session using the **unlock** command
to provide a 2-step verification code.  The user keychain may also be set directly using the **setkeychain** command.  In this case,
the **walletpassphrase** command may be used subsequently to encrypt the keychain in-memory in BitGoD.

# Production

As mentioned previously, BitGoD defaults to using BitGo's test environment, which uses testnet coins. In order to use the production BitGo environment, you can use the **-env** command line flag.
The ports used by BitGoD by default in prod and test are the same as those used by bitcoind, plus 1000.

```
$ bitgod -env prod
JSON-RPC server active on localhost:9332
```

# Config File

BitGoD can be configured entirely using the command line arguments, or it can read a config file which uses the same option names. The config file is specified with the **-conf** option, or read from */etc/bitgod.conf* by default. There are some example config files in the **bin** directory of the package.  If an option is set in the config file, as well as directly on the command line, the command line argument takes precedence.

# Proxy Configuration

BitGoD can proxy non-wallet commands to a local bitcoind instance.
Assuming you have a testnet version of bitcoind running on the local machine with username **bitcoinrpc** and password **password**, run BitGoD with a proxy as follows:

```
$ ./bitgod -proxyhost localhost -proxy true -proxyport 18332 -proxyuser bitcoinrpc -proxypassword password
Connected to proxy bitcoind at localhost:18332
{ version: 109900,
  protocolversion: 70002,
  walletversion: 60000,
  balance: 1.49990001,
  blocks: 319313,
  timeoffset: 0,
  connections: 8,
  proxy: '',
  difficulty: 1,
  testnet: true,
  keypoololdest: 1421362407,
  keypoolsize: 96,
  unlocked_until: 0,
  paytxfee: 0,
  relayfee: 0.00001,
  errors: 'This is a pre-release test build - use at your own risk - do not use for mining or merchant applications' }
JSON-RPC server active on localhost:19332

```

Once the proxy is connected, running **getinfo** against BitGoD should look something like this (note the proxy information from calling getinfo on bitcoind is now included):

```
$ bitcoin-cli -rpcport=19332 getinfo
{
    "bitgod" : true,
    "version" : "0.2.0",
    "testnet" : true,
    "token" : false,
    "wallet" : false,
    "keychain" : false,
    "paytxfee" : 0.00010000,
    "proxy" : {
        "version" : 109900,
        "protocolversion" : 70002,
        "blocks" : 319313,
        "timeoffset" : 0,
        "connections" : 8,
        "proxy" : "",
        "difficulty" : 1,
        "testnet" : true,
        "unlocked_until" : 0,
        "relayfee" : 0.00001000,
        "errors" : ""
    }
}
```

# Validation

One of the additional benefits of running connected to a local bitcoind instance, is that it allows independent verification
of data retrieved from the BitGo API. For instance, let's say you were using the **listtransactions** API to get information
about customer deposits to your site, and you wanted to credit the customer's balance once a deposit transaction had 6+ confirmations.
What if you received information about a deposit that never existed, and then allowed the customer to withdraw BTC based on that?
Of course, BitGo prides itself in serving accurate blockchain data, but we also believe in the value of checks and balances, and in eliminating single points of failure.  Validation currently only affects **listtransactions**, but its scope will increase over time.

Validation has two modes: loose and strict.

Strict mode validates for each tx output that is returned:
 *  the txid exists in local bitcoind
 *  the blockhash exists in local bitcoind
 *  the value and address match the information in bitcoind
 *  the output's transaction is included in the specified block
 *  the output's block has the specified height / confirms [ for 1-confirm and higher ]

Strict mode **will** produce occasional validation errors, due to race conditions which are entirely normal in a decentralized network. Sometimes, BitGo may have a block or even two that your local bitcoind does not have. Other times, your local bitcoind may be ahead, so BitGo under-reports the number of confirms.

In order to reduce the error rate, we currently recommend running in loose mode, which is more forgiving of validation of 1-confirm transactions.

Example of enabling validation:

```
$ ./bitgod -validate=loose -proxy=true -proxyhost=localhost -proxyport=18332 -proxyuser=bitcoinrpc -proxypassword=password
```

# Basic Auth

BitGoD supports basic auth in the same manner as bitcoind. The user and password can be set with the **rpcuser** and **rpcpassword**
config file options, or the corresponding command line flags.

# SSL over JSON RPC

If you are going to be running bitgod from a remote location to where calls will be made, we recommend the use of the **rpcssl** option to secure communications.  