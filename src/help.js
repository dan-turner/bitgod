
help = {};

help.getnewaddress = 'getnewaddress ( "account" )\
Returns a new Bitcoin address for receiving payments.\
If \'account\' is specified (DEPRECATED), it is added to the address book\
so payments received with the address will be credited to \'account\'\
\
Result:\
"bitcoinaddress"    (string) The new bitcoin address\
\
Examples:
> bitcoin-cli getnewaddress';



== Blockchain ==
** getbestblockhash
** getblock "hash" ( verbose )
** getblockchaininfo
** getblockcount
** getblockhash index
** getblockheader "hash" ( verbose )
** getchaintips
** getdifficulty
** getmempoolinfo
** getrawmempool ( verbose )
** gettxout "txid" n ( includemempool )
** gettxoutproof ["txid",...] ( blockhash )
** gettxoutsetinfo
** verifychain ( checklevel numblocks )
** verifytxoutproof "proof"

== Control ==
getinfo
help ( "command" )
stop

== Network ==
** addnode "node" "add|remove|onetry"
** clearbanned
** disconnectnode "node"
** getaddednodeinfo dns ( "node" )
** getconnectioncount
** getnettotals
** getnetworkinfo
** getpeerinfo
** listbanned
** ping
** setban "ip(/netmask)" "add|remove" (bantime) (absolute)

== Rawtransactions ==
** createrawtransaction [{"txid":"id","vout":n},...] {"address":amount,"data":"hex",...} ( locktime )
** decoderawtransaction "hexstring"
** decodescript "hex"
** fundrawtransaction "hexstring" includeWatching
** getrawtransaction "txid" ( verbose )
** sendrawtransaction "hexstring" ( allowhighfees )
** signrawtransaction "hexstring" ( [{"txid":"id","vout":n,"scriptPubKey":"hex","redeemScript":"hex"},...] ["privatekey1",...] sighashtype )

== Util ==
** createmultisig nrequired ["key",...]
estimatefee nblocks
estimatepriority nblocks
estimatesmartfee nblocks
estimatesmartpriority nblocks
validateaddress "bitcoinaddress"
verifymessage "bitcoinaddress" "signature" "message"

== Wallet ==
abandontransaction "txid"
addmultisigaddress nrequired ["key",...] ( "account" )
backupwallet "destination"
dumpprivkey "bitcoinaddress"
dumpwallet "filename"
encryptwallet "passphrase"
getaccount "bitcoinaddress"
getaccountaddress "account"
getaddressesbyaccount "account"
getbalance ( "account" minconf includeWatchonly )
getnewaddress ( "account" )
getrawchangeaddress
getreceivedbyaccount "account" ( minconf )
getreceivedbyaddress "bitcoinaddress" ( minconf )
gettransaction "txid" ( includeWatchonly )
getunconfirmedbalance
getwalletinfo
importaddress "address" ( "label" rescan p2sh )
importprivkey "bitcoinprivkey" ( "label" rescan )
importpubkey "pubkey" ( "label" rescan )
importwallet "filename"
keypoolrefill ( newsize )
listaccounts ( minconf includeWatchonly)
listaddressgroupings
listlockunspent
listreceivedbyaccount ( minconf includeempty includeWatchonly)
listreceivedbyaddress ( minconf includeempty includeWatchonly)
listsinceblock ( "blockhash" target-confirmations includeWatchonly)
listtransactions ( "account" count from includeWatchonly)
listunspent ( minconf maxconf  ["address",...] )
lockunspent unlock [{"txid":"txid","vout":n},...]
move "fromaccount" "toaccount" amount ( minconf "comment" )
sendfrom "fromaccount" "tobitcoinaddress" amount ( minconf "comment" "comment-to" )
sendmany "fromaccount" {"address":amount,...} ( minconf "comment" ["address",...] )
sendtoaddress "bitcoinaddress" amount ( "comment" "comment-to" subtractfeefromamount )
setaccount "bitcoinaddress" "account"
settxfee amount
signmessage "bitcoinaddress" "message"
