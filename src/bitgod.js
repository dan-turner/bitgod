// Copyright 2014 BitGo, Inc.  All Rights Reserved.
//

var ArgumentParser = require('argparse').ArgumentParser;
var bitgo = require('bitgo');
var rpc = require('json-rpc2');
var Q = require('q');
var fs = require('fs');
var _ = require('lodash');
_.string = require('underscore.string');

var BitGoD = function () {
};

BitGoD.prototype.getArgs = function() {
  var parser = new ArgumentParser({
    version: '0.1',
    addHelp:true,
    description: 'BitGoD'
  });

  parser.addArgument(
    ['-prod'], {
      action: 'storeTrue',
      help: 'Use prod network (default is testnet)'
  });

  parser.addArgument(
    ['-rpcbind'], {
      help: 'Bind to given address to listen for JSON-RPC connections (default: localhost)',
      defaultValue: 'localhost'
  });

  parser.addArgument(
    ['-rpcport'], {
      help: 'Listen for JSON-RPC connections on RPCPORT (default: 9332 or testnet: 19332)'
  });

  parser.addArgument(
    ['-proxyhost'], {
      help: 'Host for proxied bitcoind JSON-RPC',
      defaultValue: 'localhost'
  });

  parser.addArgument(
    ['-proxyport'], {
      help: 'Port for proxied bitcoind JSON-RPC (default: 8332 or testnet: 18332)',
      defaultValue: 18332
  });

  parser.addArgument(
    ['-proxyuser'], {
      help: 'Username for proxied bitcoind JSON-RPC',
      defaultValue: 'bitcoinrpc'
  });

  parser.addArgument(
    ['-proxypassword'], {
      help: 'Password for proxied bitcoind JSON-RPC',
  });

  parser.addArgument(
    ['-proxy'], {
      action: 'storeTrue',
      help: 'Proxy to bitcoind JSON-RPC backend for non-wallet commands'
  });

  return parser.parseArgs();
};

BitGoD.prototype.setupProxy = function() {
  var self = this;

  if (this.client) {
    throw new Error('proxy already set up');
  }

  var commandGroups = {
    blockchain: 'getbestblockhash getblock getblockchaininfo getblockcount getblockhash getchaintips getdifficulty getmempoolinfo getrawmempool gettxout gettxoutsetinfo verifychain',
    control: 'getinfo help',
    mining: 'getmininginfo getnetworkhashps prioritisetransaction submitblock',
    network: 'addnode getaddednodeinfo getconnectioncount getnettotals getnetworkinfo getpeerinfo ping',
    tx: 'createrawtransaction decoderawtransaction decodescript getrawtransaction sendrawtransaction signrawtransaction',
    util: 'createmultisig estimatefee estimatepriority validateaddress verifymessage'
  };

  var proxyPort = this.args.proxyport || (this.bitgo.network === 'prod' ? 8332 : 18332);

  this.client = rpc.Client.$create(
    proxyPort,
    this.args.proxyhost,
    this.args.proxyuser,
    this.args.proxypassword
  );

  var proxyCommand = function(cmd) {
    self.server.expose(cmd, function(args, opt, callback) {
      self.client.call(cmd, args, callback);
    });
  };

  // Proxy all the commands
  for (var group in commandGroups) {
    commandGroups[group].split(' ').forEach(proxyCommand);
  }
};

BitGoD.prototype.run = function() {
  this.args = this.getArgs();

  var network = 'testnet';
  if (process.env.BITGO_NETWORK === 'prod' || this.args.prod) {
    network = 'testnet';
  }

  bitgo.setNetwork(network);
  this.bitgo = new bitgo.BitGo({
    useProduction: network === 'prod'
  });

  this.server = rpc.Server.$create({
    'websocket': true,
    'headers': {
      'Access-Control-Allow-Origin': '*',
    }
  });

  if (this.args.proxy) {
    this.setupProxy();
  }

  var port = this.args.rpcport || (this.bitgo.network === 'prod' ? 9332 : 19332);
  this.server.listen(port, this.args.rpcbind);
};

exports = module.exports = BitGoD;