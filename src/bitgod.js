// Copyright 2014 BitGo, Inc.  All Rights Reserved.
//

var ArgumentParser = require('argparse').ArgumentParser;
var assert = require('assert');
var bitgo = require('bitgo');
var bitcoin = require('bitcoinjs-lib');
var rpc = require('json-rpc2');
var Q = require('q');
var fs = require('fs');
var _ = require('lodash');
_.string = require('underscore.string');
var pjson = require('../package.json');
var BITGOD_VERSION = pjson.version;

// Q.longStackSupport = true;

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

  parser.addArgument(
    ['-validate'], {
      nargs: '?',
      choices: ['loose', 'strict'],
      constant: 'loose',
      help: 'Validate transaction data against local bitcoind (requires -proxy)'
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
    control: 'help',
    mining: 'getmininginfo getnetworkhashps prioritisetransaction submitblock',
    network: 'addnode getaddednodeinfo getconnectioncount getnettotals getnetworkinfo getpeerinfo ping',
    tx: 'createrawtransaction decoderawtransaction decodescript getrawtransaction sendrawtransaction signrawtransaction',
    util: 'createmultisig estimatefee estimatepriority verifymessage'
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

  // Setup promis-ified method to call a method in bitcoind
  this.callLocalMethod = Q.nbind(this.client.call, this.client);

  // Verify we can actually connect
  return this.callLocalMethod('getinfo', [])
  .catch(function(err) {
    throw new Error('Could not connect to proxy');
  });
};

BitGoD.prototype.getTransactionLocal = function(txhash) {
  return this.callLocalMethod('getrawtransaction', [txhash])
  .then(function(hex) {
    return bitcoin.Transaction.fromHex(hex);
  });
};

BitGoD.prototype.getTransactionsLocal = function(txhashes) {
  var self = this;
  return Q.allSettled(
    txhashes.map(function(txhash) {
      return self.getTransactionLocal(txhash);
    })
  )
  .then(function(result) {
    return _.pluck(result, 'value');
  });
};

BitGoD.prototype.getBlockLocal = function(blockhash) {
  return this.callLocalMethod('getblock', [blockhash]);
};

BitGoD.prototype.getBlocksLocal = function(blockhashes) {
  var self = this;
  return Q.allSettled(
    blockhashes.map(function(blockhash) {
      return self.getBlockLocal(blockhash);
    })
  )
  .then(function(result) {
    return _.pluck(result, 'value');
  });
};

BitGoD.prototype.ensureWallet = function() {
  if (!this.wallet) {
    throw new Error('Not connected to BitGo wallet');
  }
};

BitGoD.prototype.getSigningKeychain = function() {
  if (!this.keychain) {
    throw new Error('No keychain');
  }
  if (!this.keychain.xprv && !this.keychain.encryptedXprv) {
    throw new Error('No keychain xprv');
  }
  var xprv = this.keychain.xprv;
  if (!xprv) {
    if (!this.passphrase) {
      throw this.error('Error: Please use walletpassphrase or setkeychain first.', -13);
    }
    xprv = this.bitgo.decrypt({
      password: this.passphrase,
      input: this.keychain.encryptedXprv
    });
  }
  return {
    xpub: this.keychain.xpub,
    path: this.keychain.path,
    xprv: xprv
  };
};

BitGoD.prototype.toBTC = function(satoshis) {
  return (satoshis / 1e8);
};

BitGoD.prototype.getNumber = function(val, defaultValue) {
  if (typeof(val) === 'undefined') {
    return defaultValue;
  }
  var result = Number(val);
  if (isNaN(result)) {
    throw this.error('value is not a number', -1);
  }
  return result;
};

BitGoD.prototype.getInteger = function(val, defaultValue) {
  var number = this.getNumber(val, defaultValue);
  var integer = parseInt(number);
  if (integer != number) {
    throw this.error('value is type real, expected int', -1);
  }
  return integer;
};

BitGoD.prototype.ensureBlankAccount = function(account) {
  if (typeof(account) !== 'undefined' && account !== '') {
    throw new Error('accounts not supported - use blank account only');
  }
};

BitGoD.prototype.error = function(message, code) {
  if (!code) {
    throw new Error(message);
  }
  var MyError = rpc.Error.AbstractError.$define('MyError', {code: code});
  return new MyError(message);
};

BitGoD.prototype.log = function() {
  return console.log.apply(console, arguments);
};

BitGoD.prototype.modifyError = function(err) {
  var message;
  if (typeof(err) === 'string') {
    message = err;
  } else {
    message = err.message;
  }
  if (!message) {
    return err;
  }
  if (message === 'Insufficient funds') {
    return this.error('Insufficient funds', -6);
  }
  if (message.indexOf('invalid bitcoin address') !== -1) {
    return this.error('Invalid Bitcoin address', -5);
  }
  if (message.indexOf('invalid amount') !== -1) {
    return this.error('Invalid amount', -3);
  }
  if (message.indexOf('must have at least one recipient') !== -1) {
    return this.error('Transaction amounts must be positive', -6);
  }
  return err;
};

BitGoD.prototype.getWallet = function(id) {
  id = id || this.wallet.id();
  return this.bitgo.wallets().get({id: id});
};

BitGoD.prototype.handleNOOP = function() {
  return "";
};

BitGoD.prototype.handleSetToken = function(token) {
  var self = this;
  this.bitgo._token = token;
  return this.bitgo.me()
  .then(function(user) {
    self.bitgo._user = user;
    return 'Authenticated as BitGo user: ' + user.username;
  });
};

BitGoD.prototype.handleSetWallet = function(walletId) {
  var self = this;
  if (this.wallet && this.wallet.id() === walletId) {
    return 'Set wallet: ' + walletId;
  }
  return this.getWallet(walletId)
  .then(function(wallet) {
    self.wallet = wallet;
    return 'Set wallet: ' + wallet.id();
  });
};

BitGoD.prototype.handleValidateAddress = function(address) {
  var result = {
    valid: this.bitgo.verifyAddress({ address: address })
  };
  if (!result.valid) {
    return result;
  }
  result.address = address;
  result.scriptPubKey = bitcoin.Address.fromBase58Check(address).toOutputScript().toHex();
  // Missing fields for our own addresses (need API support):
  // ismine
  // iswatchonly
  // isscript
  // pubkey
  // iscompressed
  // account
  return result;
};

BitGoD.prototype.handleSession = function() {
  return this.bitgo.session()
  .then(function(session) {
    if (session.unlock) {
      session.unlock.secondsRemaining = Math.floor((new Date(session.unlock.expires) - new Date()) / 1000);
    }
    return session;
  });
};

BitGoD.prototype.handleUnlock = function(otp, seconds) {
  seconds = this.getNumber(seconds, 600);
  return this.bitgo.unlock({otp: otp, duration: seconds})
  .then(function() {
    return 'Unlocked';
  });
};

BitGoD.prototype.handleLock = function() {
  return this.bitgo.lock()
  .then(function() {
    return "Locked";
  });
};

BitGoD.prototype.handleFreezeWallet = function(seconds) {
  var self = this;
  seconds = this.getNumber(seconds);
  this.ensureWallet();
  return this.wallet.freeze({ duration: seconds });
};

/**
 * Set the wallet keychain xprv, after fetching the keychain from the server, and validating
 * the xprv against the xpub.  This call can be used by customers who don't have an encryptedXprv
 * set on their server-side keychain.
 *
 * @param   {String} xprv   the BIP32 xprv for the user's keychain
 * @returns {String}        message on success, or throws
 */
BitGoD.prototype.handleSetKeychain = function(xprv) {
  var self = this;

  this.ensureWallet();
  if (xprv === '') {
    delete this.keychain;
    return 'Keychain removed';
  }
  var bip32;
  try {
    bip32 = new bitgo.BIP32(xprv);
    this.ensureWallet();
    if (bip32.extended_private_key_string() !== xprv) {
      throw new Error();
    }
  } catch (err) {
    throw new Error('Invalid keychain xprv');
  }
  var xpub = bip32.extended_public_key_string();

  return this.bitgo.keychains().get({xpub: xpub})
  .then(function(keychain) {
    keychain.xprv = xprv;
    self.keychain = keychain;
    return 'Keychain set';
  });
};

/**
 * Set the wallet passphrase for a specified number of seconds.
 * Has slightly different behavior if a keychain is already set (using setkeychain)
 *
 * If keychain is set:
 *   - we encrypt the xprv with the passphrase, and then dump the unencrypted version
 *
 * If keychain is not set, grab from the server, and attempt to decrypt encryptedXprv.
 * If it succeeds, then keep the passphrase in memory for the specified time period.
 *
 * @param   {String} passphrase    the passphrase
 * @param   {Number} timeout       the timeout in seconds
 * @returns {Promise}              undefined on success, or throws
 */
BitGoD.prototype.handleWalletPassphrase = function(passphrase, timeout) {
  var self = this;
  timeout = this.getNumber(timeout, 0);
  if (!timeout) {
    throw new Error('timeout must be specified');
  }
  var error = this.error('Error: The wallet passphrase entered was incorrect.', -14);
  this.ensureWallet();

  return Q().then(function() {
    // If we don't have a keychain set yet, fetch it from the wallet
    if (!self.keychain) {
      return self.bitgo.keychains().get({xpub: self.wallet.keychains[0].xpub })
      .then(function(keychain) {
        self.keychain = keychain;
      });
    }
  })
  .then(function() {
    if (self.keychain.encryptedXprv) {
      try {
        self.bitgo.decrypt({
          password: passphrase,
          input: self.keychain.encryptedXprv
        });
      } catch (e) {
        throw error;
      }
    }
    // Handle case where we already have a keychain set, just not encrypted
    if (self.keychain.xprv) {
      self.keychain.encryptedXprv = self.bitgo.encrypt({
        password: passphrase,
        input: self.keychain.xprv
      });
    }

    // Make sure we don't keep unencrypted version
    delete self.keychain.xprv;

    self.passphrase = passphrase;

    // Delete the passphrase in timeout seconds (or immediately if <= 0)
    setTimeout(function() {
      delete self.passphrase;
    }, timeout * 1000);
  });
};

BitGoD.prototype.handleWalletLock = function() {
  delete this.passphrase;
};

BitGoD.prototype.newAddress = function(chain) {
  this.ensureWallet();
  return this.wallet.createAddress({chain: chain})
  .then(function(address) {
    return address.address;
  });
};

BitGoD.prototype.handleGetNewAddress = function() {
  return this.newAddress(0);
};

BitGoD.prototype.handleGetRawChangeAddress = function() {
  return this.newAddress(1);
};

BitGoD.prototype.getBalanceFromUnspents = function(minConfirms, maxConfirms) {
  return this.handleListUnspent(minConfirms, maxConfirms)
  .then(function(unspents) {
    return self.toBTC(
      Math.round(unspents.reduce(function(prev, unspent) { return prev + unspent.satoshis; }, 0))
    );
  });
};

BitGoD.prototype.getBalance = function(minConfirms) {
  assert(typeof(minConfirms) !== 'undefined');
  var self = this;
  return Q().then(function() {
    if (minConfirms > 1) {
      return self.getBalanceFromUnspents(minConfirms);
    }
    return self.getWallet()
    .then(function(wallet) {
      switch (minConfirms) {
        case 0:
          return self.toBTC(wallet.balance());
        case 1:
          return self.toBTC(wallet.confirmedBalance());
      }
    });
  }).then(function(balance) {
    return balance;
  });
};

BitGoD.prototype.handleGetBalance = function(account, minConfirms) {
  this.ensureWallet();
  this.ensureBlankAccount(account);
  minConfirms = this.getNumber(minConfirms, 1);
  return this.getBalance(minConfirms);
};

BitGoD.prototype.handleGetUnconfirmedBalance = function() {
  var self = this;
  this.ensureWallet();
  return this.getWallet()
  .then(function(wallet) {
    return self.toBTC(wallet.balance() - wallet.confirmedBalance());
  });
};

BitGoD.prototype.handleListAccounts = function(minConfirms) {
  return this.handleGetBalance('', minConfirms)
  .then(function(balance) {
    return {
      "": balance
    };
  });
};

BitGoD.prototype.handleListUnspent = function(minConfirms, maxConfirms, addresses) {
  this.ensureWallet();
  var self = this;
  minConfirms = this.getNumber(minConfirms, 1);
  maxConfirms = this.getNumber(maxConfirms, 9999999);

  return this.wallet.unspents()
  .then(function(unspents) {
    return unspents.map(function(u) {
      return {
        txid: u.tx_hash,
        vout: u.tx_output_n,
        address: u.address,
        account: '',
        scriptPubKey: u.script,
        redeemScript: u.redeemScript,
        amount: self.toBTC(u.value),
        satoshis: u.value,  // non-standard field
        confirmations: u.confirmations
      };
    })
    .filter(function(u) {
      return (u.confirmations >= minConfirms && u.confirmations <= maxConfirms);
    });
  });
};

/**
 * Validate a list of tx outputs against the local bitcoind
 * The following are checked for each output:
 *  1. The txid exists
 *  2. The blockhash exists
 *  3. The value matches
 *  4. The address matches
 *  5. The output's transaction is included in the specified block
 *  6. The output's block has the specified height / confirms
 *
 * @param   {Array} outputs   list of outputs (in form returned by listtransactions)
 * @returns {Array}           the outputs, or throws error
 */
BitGoD.prototype.validateTxOutputs = function(outputs) {
  var self = this;

  var throwValidationError = function(output, msg, serverVal, localVal) {
    if (output) {
      console.log('Validation failure for output:');
      console.dir(output);
    }
    var prefix = 'Validation failed';
    if (output) {
      prefix = prefix + ' for output ' + output.txid + ':' + output.vout;
    }
    var postfix = "";
    if (serverVal && localVal) {
      postfix = " " + JSON.stringify({server: serverVal, local: localVal});
    }
    throw new Error(prefix + ': ' + msg + postfix);
  };

  // Divide outputs into 3 sets (0-confirm, 1-confirm, more-than-1-confirm)
  var outputGroup = function(output) {
    return output.confirmations > 1 ? 2 : output.confirmations;
  };
  var groups = [0, 1, 2];

  var outputGroups = groups.map(function(group) {
    return outputs.filter(function(o) { return outputGroup(o) === group; });
  });

  // Create corresponding sets of txids
  var txidGroups = outputGroups.map(function(outputSet) {
    return _.chain(outputSet).pluck('txid').uniq().value();
  });

  // Create corresponding sets of blockids
  var blockidGroups = [
    [],
    _.chain(outputGroups[1]).pluck('blockhash').uniq().value(),
    _.chain(outputGroups[2]).pluck('blockhash').uniq().value()
  ];
  // there should only be 1 top block
  assert(blockidGroups[1].length <= 1);

  return Q.all([
    self.getTransactionsLocal(txidGroups[0]),
    self.getTransactionsLocal(txidGroups[1]),
    self.getTransactionsLocal(txidGroups[2]),
    [],
    self.getBlocksLocal(blockidGroups[1]),
    self.getBlocksLocal(blockidGroups[2])
  ])
  .then(function(result) {
    var txGroups = result.slice(0, 3);
    var blockGroups = result.slice(3, 6);

    // Build sets of maps from txid to tx
    var txByIdGroups = groups.map(function(group) {
      return _.zipObject(txidGroups[group], txGroups[group]);
    });

    // Build sets of maps from blockid to block
    var blockByIdGroups = groups.map(function(group) {
      return _.zipObject(blockidGroups[group], blockGroups[group]);
    });

    // In strict mode, we validate anything with 1 confirm or more. This means
    // validation can fail if the local bitcoind does not have the current top block.
    // In normal (loose) validation mode, we only require existence of blocks/transactions
    // which have 2+ confirms.
    var minGroupToValidate = self.validate === 'strict' ? 1 : 2;

    groups.slice(minGroupToValidate, 2).forEach(function(group) {
      var failedTransactions = txidGroups[group].filter(function(txid) { return !txByIdGroups[group][txid]; });
      if (failedTransactions.length > 0) {
        throwValidationError(null, 'Missing txids ' + failedTransactions.join(', '));
      }

      var failedBlocks = blockidGroups[group].filter(function(blockid) { return !blockByIdGroups[group][blockid]; });
      if (failedBlocks.length > 0) {
        throwValidationError(null, 'Missing blocks ' + failedBlocks.join(', '));
      }
    });

    outputs.forEach(function(o) {
      var group = outputGroup(o);
      var txoutStr = [o.txid, o.vout].join(':');
      var tx = txByIdGroups[group][o.txid];

      // If we don't have the tx, just return. We checked existence above.
      if (!tx) {
        assert(group < minGroupToValidate);
        return;
      }
      var txout = tx.outs[o.vout];

      // validate amount
      if (o.satoshis !== txout.value) {
        throwValidationError(o, 'Amount mismatch', o.satoshis, txout.value);
      }

      // validate address
      var address = bitcoin.Address.fromOutputScript(txout.script, this.network).toBase58Check();
      if (o.address !== address) {
        throwValidationError(o, 'Address mismatch', o.address, address);
      }

      // validate it's in the right block, and confirms matches
      if (o.blockhash || o.confirmations) {
        if (!o.blockhash) {
          throwValidationError(o, 'Has non-zero confirms but missing blockhash');
        }
        if (!o.confirmations) {
          throwValidationError(o, 'Has blockhash but missing confirms');
        }
        block = blockByIdGroups[group][o.blockhash];

        // If we're missing block, just return.
        if (!block) {
          assert(group < minGroupToValidate);
          return;
        }

        // validate tx included in block
        if (block.tx.indexOf(o.txid) === -1) {
          throwValidationError(o, 'Not included in block ' + block.hash);
        }

        // validate height matches
        if (block.height !== o.height) {
          throwValidationError(o, 'Height mismatch', o.height, block.height);
        }

        // validate confirms match. We allow us to under-report confirms by up to 2, but only
        // be ahead by up to 1.
        var confirmDifference = o.confirmations - block.confirmations;
        if (confirmDifference < -2) {
          throwValidationError(o, 'Confirms too low', o.confirmations, block.confirmations);
        }
        if (confirmDifference > 1) {
          throwValidationError(o, 'Confirms too high', o.confirmations, block.confirmations);
        }
      }
    });

    return outputs;
  });
};

BitGoD.prototype.handleListTransactions = function(account, count, from) {
  this.ensureWallet();
  var self = this;

  this.ensureBlankAccount(account);
  count = this.getInteger(count, 10);
  from = this.getInteger(from, 0);

  if (count < 0) {
    throw this.error('Negative count', -8);
  }
  if (from < 0) {
    throw this.error('Negative from', -8);
  }

  var outputList = [];
  var getTransactionsInternal = function(skip) {

    return self.wallet.transactions({ limit: 500, skip: skip })
    .then(function(res) {

      res.transactions.every(function(tx) {

        for (var index = 0; index < tx.entries.length; ++index) {
          if (tx.entries[index].account == self.wallet.id()) {
            tx.value = tx.entries[index].value;
            break;
          }
        }

        var outputCount = tx.outputs.length;
        tx.outputs.forEach(function(output, outputIndex) {
          // Skip the output if it's an overall spend, but we have a positive output to us that
          // is last (the change address)
          // or if it's an overall receive, and there's a positive output elsewhere.
          // TODO: fix this the right way to know whether it's change address if change
          // addresses are no longer always put last.
          if ((tx.value < 0 && output.isMine && output.vout === outputCount - 1) ||
              (tx.value > 0 && !output.isMine) ) {
            return;
          }
          output.netValue = output.isMine ? output.value : -output.value;
          var record = {
            account: '',
            address: output.account,
            category:  output.isMine ? 'receive' : 'send',
            amount: self.toBTC(output.netValue),
            vout: output.vout,
            confirmations: tx.confirmations,
            blockhash: tx.blockhash,
            // blockindex: 0,  // don't have it
            // blocktime: '',  // don't have it
            txid: tx.id,
            time: new Date(tx.date).getTime() / 1000,
            timereceived: new Date(tx.date).getTime() / 1000,

            // Non-standard fields (could strip after validation)
            height: tx.height,
            satoshis: output.value
          };
          if (tx.value < 0) {
            record.fee = self.toBTC(-tx.fee);
          }
          outputList.push(record);
        });
        return (outputList.length < count + from);
      });

      if (outputList.length >= count + from || res.count <= 0) {
        return;
      } else {
        return getTransactionsInternal(skip + res.count);
      }
    });
  };

  return getTransactionsInternal(0)
  .then(function() {
    return outputList
    .slice(from, count + from)
    .sort(function(a, b) {
      if (b.confirmations != a.confirmations) {
        return b.confirmations - a.confirmations;
      }
      if (b.amount != a.amount) {
        return b.amount - a.amount;
      }
      if (b.address !== a.address) {
        return (b.address > a.address) ? 1 : -1;
      }
      return (b.txid > a.txid ? 1 : -1);
    });
  })
  .then(function(outputs) {
    if (!self.validate) {
      return outputs;
    }
    return self.validateTxOutputs(outputs);
  });
};

BitGoD.prototype.handleSendToAddress = function(address, btcAmount, comment) {
  this.ensureWallet();
  var self = this;
  var satoshis = Math.round(Number(btcAmount) * 1e8);

  return this.getWallet()
  .then(function(wallet) {
    var recipients = {};
    recipients[address] = satoshis;
    return self.wallet.createTransaction({
      minConfirms: 1,
      recipients: recipients,
      keychain: self.getSigningKeychain()
    });
  })
  .then(function(tx) {
    return self.wallet.sendTransaction({
      tx: tx.tx,
      message: comment
    });
  })
  .then(function(result) {
    return result.hash;
  })
  .catch(function(err) {
    throw self.modifyError(err);
  });
};

BitGoD.prototype.handleSendMany = function(account, recipients, minConfirms, comment) {
  this.ensureWallet();
  var self = this;
  this.ensureBlankAccount(account);
  minConfirms = this.getNumber(minConfirms, 1);

  Object.keys(recipients).forEach(function(destinationAddress) {
    recipients[destinationAddress] = Math.round(Number(recipients[destinationAddress]) * 1e8);
  });

  return this.getWallet()
  .then(function(wallet) {
    return self.wallet.createTransaction({
      minConfirms: minConfirms,
      recipients: recipients,
      keychain: self.getSigningKeychain()
    });
  })
  .then(function(tx) {
    return self.wallet.sendTransaction({
      tx: tx.tx,
      message: comment
    });
  })
  .then(function(result) {
    return result.hash;
  })
  .catch(function(err) {
    throw self.modifyError(err);
  });
};

BitGoD.prototype.handleSendFrom = function(account, address, amount, minConfirms, comment) {
  var recipients = {};
  recipients[address] = amount;
  return this.handleSendMany(account, recipients, minConfirms, comment);
};

BitGoD.prototype.handleGetWalletInfo = function() {
  var self = this;
  this.ensureWallet();

  return this.getWallet()
  .then(function(wallet) {
    return {
      walletversion: 'bitgo',
      balance: self.toBTC(wallet.confirmedBalance()),
      unconfirmedbalance: self.toBTC(wallet.balance() - wallet.confirmedBalance()),
      //unlocked_until: wallet.wallet.unlock
    };
  });
};

BitGoD.prototype.handleGetInfo = function() {
  var self = this;
  var promises = [];
  var hasToken = !!this.bitgo._token;
  promises.push(self.client ? self.callLocalMethod('getinfo', []) : undefined);
  promises.push(hasToken ? self.getBalance(1) : undefined);

  return Q.all(promises)
  .spread(function(proxyInfo, balance) {
    var info = {
      bitgod: true,
      version: BITGOD_VERSION,
      testnet: bitgo.network === 'testnet',
      token: hasToken,
      wallet: self.wallet ? self.wallet.id() : false,
      keychain: !!self.keychain,
      balance: balance,
      paytxfee: 0.0001,
    };
    if (proxyInfo) {
      // Strip irrelevant fields, since wallet functionality is not used
      info.proxy = _.omit(proxyInfo, ['balance', 'walletversion', 'keypoololdest', 'keypoolsize', 'paytxfee']);
    }
    return info;
  });
};

BitGoD.prototype.handleNotImplemented = function() {
  throw this.error('Not implemented', -32601);
};

/**
 * Expose an RPC method
 * @param   {String} name   the method name
 * @param   {Function} method   the @method
 */
BitGoD.prototype.expose = function(name, method, noLogArgs) {
  var self = this;
  this.server.expose(name, function(args, opt, callback) {
    var argString = noLogArgs ? '' : (' ' + JSON.stringify(args));
    self.log('RPC call: ' + name + argString);
    return Q().then(function() {
      return method.apply(self, args);
    })
    .catch(function(err) {
      console.log(err.stack);
      throw err;
    })
    .nodeify(callback);
  });
};

BitGoD.prototype.run = function() {
  this.args = this.getArgs();
  var self = this;

  // Configure bitcoin network (prod/testnet)
  var network = 'testnet';
  if (process.env.BITGO_NETWORK === 'prod' || self.args.prod) {
    network = 'prod';
  }
  bitgo.setNetwork(network);
  this.network = bitcoin.networks[network];

  // Instantiate BitGo
  self.bitgo = new bitgo.BitGo({
    useProduction: network === 'prod'
  });

  // Set up RPC server
  self.server = rpc.Server.$create({
    'websocket': true,
    'headers': {
      'Access-Control-Allow-Origin': '*',
    }
  });

  // Validation vs bitcoind
  if (self.args.validate) {
    if (!self.args.proxy) {
      throw new Error('validate option requires a proxy bitcoind');
    }
    self.validate = self.args.validate;
    console.log('Validating in ' + self.validate + ' mode');
  }

  // Will not implement
  var willNotImplement = 'addmultisigaddress backupwallet dumpprivkey dumpwallet getaccount getaccountaddress  importaddress importprivkey importwallet keypoolrefill listaddressgroupings listlockunspent listreceivedbyaccount lockunspent move setaccount signmessage';
  willNotImplement.split(' ').forEach(function(api) {
    self.expose(api, self.handleNotImplemented);
  });

  // Just not implemented yet
  var notImplemented = 'encryptwallet getaddressesbyaccount getreceivedbyaccount getreceivedbyaddress gettransaction listsinceblock settxfee';
  notImplemented.split(' ').forEach(function(api) {
    self.expose(api, self.handleNotImplemented);
  });

  // BitGo-handled bitcoind methods
  self.expose('getnewaddress', self.handleGetNewAddress);
  self.expose('getrawchangeaddress', self.handleGetRawChangeAddress);
  self.expose('getbalance', self.handleGetBalance);
  self.expose('getinfo', self.handleGetInfo);
  self.expose('getwalletinfo', self.handleGetWalletInfo);
  self.expose('getunconfirmedbalance', self.handleGetUnconfirmedBalance);
  self.expose('listaccounts', self.handleListAccounts);
  self.expose('listunspent', self.handleListUnspent);
  self.expose('sendtoaddress', self.handleSendToAddress);
  self.expose('sendfrom', self.handleSendFrom);
  self.expose('listtransactions', self.handleListTransactions);
  self.expose('sendmany', self.handleSendMany);
  self.expose('validateaddress', self.handleValidateAddress);
  self.expose('walletpassphrase', self.handleWalletPassphrase, true);
  self.expose('walletlock', self.handleWalletLock);

  // BitGo-specific methods
  self.expose('settoken', self.handleSetToken, true);
  self.expose('setkeychain', self.handleSetKeychain, true);
  self.expose('setwallet', self.handleSetWallet);
  self.expose('session', self.handleSession);
  self.expose('unlock', self.handleUnlock);
  self.expose('lock', self.handleLock);
  self.expose('freezewallet', self.handleFreezeWallet);

  return Q().then(function() {
    // Proxy bitcoind
    if (self.args.proxy) {
      return self.setupProxy();
    }
  })
  .then(function() {
    // Listen
    var port = self.args.rpcport || (bitgo.network === 'prod' ? 9332 : 19332);
    self.server.listen(port, self.args.rpcbind);
    self.log('JSON-RPC server active on ' + self.args.rpcbind + ':' + port);
  })
  .catch(function(err) {
    self.log(err.message);
    // self.log(err.stack);
  })
  .done();
};

exports = module.exports = BitGoD;
