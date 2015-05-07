//
// Tests for BitGoD
// Copyright 2015, BitGo, Inc.  All Rights Reserved.
//

var assert = require('assert');
var should = require('should');
var rpc = require('json-rpc2');
var Q = require('q');
var nock = require('nock');
var pjson = require('../package.json');
var _ = require('lodash');
var results = require('./results');
var bitcoin = require('bitcoinjs-lib');

var BitGoD = require('../src/bitgod');

describe('BitGoD', function() {

  var bitgod;
  var client;
  var callRPC;

  var expectError = function() { assert(false); };

  before(function() {
    // nock.disableNetConnect();
    nock.enableNetConnect('localhost');

    // Setup RPC client and callRPC function
    client = rpc.Client.$create(19332, 'localhost', 'test', 'pass');
    var callQ = Q.nbind(client.call, client);
    callRPC = function(method) {
      return callQ(method, Array.prototype.slice.call(arguments, 1));
    };

    // Setup BitGoD
    bitgod = new BitGoD().setLoggingEnabled(false);
    return bitgod.run('-env test -rpcuser=test -rpcpassword=pass');
  });

  describe('Initialization', function(done) {

    it('basic auth fail', function(done) {
      var badClient = rpc.Client.$create(19332, 'localhost', 'test', 'badpass');
      badClient.call('getinfo', [], function(err, res) {
        err.code.should.equal(-32602);
        err.message.should.equal('Unauthorized');
        done();
      });
    });

    it('getinfo', function() {
      return callRPC('getinfo')
      .then(function(result) {
        result.bitgod.should.equal(true);
        result.version.should.equal(pjson.version);
        result.testnet.should.equal(true);
        result.token.should.equal(false);
        result.wallet.should.equal(false);
        result.keychain.should.equal(false);
        result.paytxfee.should.equal(0.0001);
      });
    });

    it('not an API', function() {
      return callRPC('wtf')
      .then(expectError, function(err) {
        err.code.should.equal(-32601);
        err.message.should.equal('Unknown RPC call "wtf"');
      });
    });

    it('not implemented', function() {
      var callNext = function(apiList) {
        if (apiList.length === 0) {
          return;
        }
        var api = apiList[0];
        return callRPC(api)
        .then(expectError, function(err) {
          err.code.should.equal(-32601);
          err.message.should.equal('Not implemented');
        })
        .then(function() {
          return callNext(apiList.slice(1));
        });
      };
      return callNext(bitgod.notImplemented);
    });
  });

  describe('Validate address', function(done) {
    it('validateaddress fails on garbage', function() {
      return callRPC('validateaddress', 'foobar')
      .then(function(result) {
        result.should.eql({isvalid: false});
      });
    });

    it('validateaddress fails on prod address', function() {
      return callRPC('validateaddress', '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa')
      .then(function(result) {

        result.should.eql({isvalid: false});
      });
    });

    it('validateaddress succeeds', function() {
      return callRPC('validateaddress', '2N4jxjW3N1XyanRYPkRYJG7CapSepg53tT2')
      .then(function(result) {
        result.isvalid.should.equal(true);
        result.address.should.equal('2N4jxjW3N1XyanRYPkRYJG7CapSepg53tT2');
        result.scriptPubKey.should.equal('a9147e18b65f2ac82c6c4407726e9201d0281068c1b687');
      });
    });

  });

  describe('No auth', function(done) {

    it('getbalance', function() {
      return callRPC('getbalance')
      .then(expectError, function(err) {
        err.code.should.equal(-32603);
        err.message.should.match(/Not connected to BitGo wallet/);
      });
    });
  });

  describe('Bad auth', function(done) {

    before(function() {
      // logged out state
      nock('https://test.bitgo.com:443')
        .get('/api/v1/user/me')
        .reply(401, {"error":"Authorization required"});
    });

    it('settoken', function() {
      return callRPC('settoken', 'bad')
      .then(expectError, function(err) {
        err.message.should.match(/Authorization required/);
      });
    });

  });

  describe('Good auth', function(done) {

    before(function() {
      nock.cleanAll();
    });

    it('settoken', function() {
      nock('https://test.bitgo.com:443')
        .get('/api/v1/user/me')
        .reply(200, {"user":{"id":"1111111111111111111111111","username":"user@domain.com"}});

      nock('https://test.bitgo.com:443')
        .get('/api/v1/wallet/2N9VaC4SDRNNnEy6G8zLF8gnHgkY6LV9PsX')
        .reply(200, {"id":"2N9VaC4SDRNNnEy6G8zLF8gnHgkY6LV9PsX","label":"Test Wallet 1","isActive":true,"type":"safehd","freeze":{"time":"2015-01-19T19:42:04.212Z","expires":"2015-01-19T19:42:14.212Z"},"adminCount":1,"private":{"keychains":[{"xpub":"xpub661MyMwAqRbcEfREDmUVK3o5wekgo2kMd8P7tZK8zrDgB454cuVJsUN5XzzwmdFRwjooWmmj6oovEZLoa66iHMBqv9JurunU6qKuCvcpMDh","path":"/0/0"},{"xpub":"xpub661MyMwAqRbcFSu5cKZMN8LdcTZ14ADiopVd6SpgCLhpENP2VXLZLcarfN1qwJYx8yuyp6QkmFWaYLk4LLDR5DMTWEMKb69UzhKXcxPP2XG","path":"/0/0"},{"xpub":"xpub661MyMwAqRbcGeVsWGCm1sagwUJS7AKJjW1GztdKx4wp1UP9xpNs5PKPqVF6xaX9jQX3Z2i6dT5oJycFEdthymPViwRAmrFggvASmbjWaeu","path":"/0/0"}]},"permissions":"admin,spend,view","admin":{},"spendingAccount":true,"confirmedBalance":81873015758,"balance":81873015758,"pendingApprovals":[]});

      return callRPC('settoken', '8996142336b3113e34522e6df56961393bb5cf690c4c8d68f3499a582c4403aa')
      .then(function(result) {
        result.should.equal('Authenticated as BitGo user: user@domain.com');
      });
    });

    it('session', function() {
      nock('https://test.bitgo.com:443')
        .get('/api/v1/user/session')
        .reply(200, {"session":{"client":"bitgo","user":"5461addd9b904dac1200003353061409","scope":["user_manage","openid","profile","wallet_create","wallet_manage_all","wallet_approve_all","wallet_spend_all","wallet_edit_all","wallet_view_all"],"expires":"2015-01-30T20:39:06.859Z","origin":"test.bitgo.com"}});

      return callRPC('session')
      .then(function(result) {
        result.client.should.equal('bitgo');
        result.user.should.equal('5461addd9b904dac1200003353061409');
        result.expires.should.equal('2015-01-30T20:39:06.859Z');
        result.origin.should.equal('test.bitgo.com');
      });
    });

    it('setwallet fails on missing wallet', function() {
      nock('https://test.bitgo.com:443')
        .get('/api/v1/wallet/2NGJUnTv3irhjo8DMWh8arp5ow584CCR7DD')
        .reply(404, {"error":"not found"});

      return callRPC('setwallet', '2NGJUnTv3irhjo8DMWh8arp5ow584CCR7DD')
      .then(expectError, function(err) {
        err.message.should.match(/not found/);
      });
    });

    it('setwallet succeeds', function() {
      return callRPC('setwallet', '2N9VaC4SDRNNnEy6G8zLF8gnHgkY6LV9PsX')
      .then(function(result) {
        result.should.equal('Set wallet: 2N9VaC4SDRNNnEy6G8zLF8gnHgkY6LV9PsX');
      });
    });

    it('setkeychain fails for invalid xprv', function() {
      var buf = new Buffer(512 / 8);
      buf.fill(0);
      var xprv = bitcoin.HDNode.fromSeedBuffer(buf).toBase58();
      return callRPC('setkeychain', xprv + 'incorrect-data-makes-xprv-invalid')
      .catch(function(err) {
        err.message.should.equal('Error: Invalid keychain xprv');
      });
    });

    it('setkeychain derives the correct public key', function() {
      // in this test, we're trying to set a keychain to which we don't have
      // the private key. as such, the setkeychain API call actually does not
      // work. However, we still want to test the logic that derives the xpub
      // from the xprv inside handleSetKeychain. As such, we mock up the
      // keychains() call.
      var buf = new Buffer(512 / 8);
      buf.fill(0);
      var bip32 = bitcoin.HDNode.fromSeedBuffer(buf);
      var xprv = bip32.toBase58();
      var xpub = bip32.neutered().toBase58();

      // mock up bitgo.keychains so we don't have to actually get a keychain
      // that exists - just make sure no error is thrown before these methods
      // are called. we need to backup the two values, bitgo and keychain, that
      // are changed when setkeychain is called, and we must return these saved
      // values to the correct values in order to not mess up the other tests.
      var bitgobackup = bitgod.bitgo;
      var keychainbackup = bitgod.keychain;
      bitgod.bitgo = {};
      bitgod.bitgo.keychains = function() {
        return {get: function(params) {
          // this is the xpub corresponding to a 512 bit seed of all 0s
          params.xpub.should.equal('xpub661MyMwAqRbcGbBpWNyiRmuKRQv1bxek4VDxEamwv5eouoLdVB8d8e29h8Y5C9R6maERkgbWZ8wguEZS69bUMzUnhsvkf6s3aabrjMyiT1k');

          return {then: function(f) {
            var keychain = {};
            return Q.all([f(keychain)]);
          }};
        }};
      };

      return callRPC('setkeychain', xprv)
      .then(function(result) {
        result[0].should.equal('Keychain set');
        bitgod.keychain = keychainbackup;
        bitgod.bitgo = bitgobackup;
      })
      .catch(function() {
        bitgod.keychain = keychainbackup;
        bitgod.bitgo = bitgobackup;
        throw new Error('setkeychain failed');
      });
    });

    it('walletpassphrase fails before unlock', function() {
      nock('https://test.bitgo.com:443')
        .post('/api/v1/keychain/xpub661MyMwAqRbcEfREDmUVK3o5wekgo2kMd8P7tZK8zrDgB454cuVJsUN5XzzwmdFRwjooWmmj6oovEZLoa66iHMBqv9JurunU6qKuCvcpMDh', {})
        .reply(401, {"error":"needs unlock","needsOTP":true,"needsUnlock":true});

      return callRPC('walletpassphrase', 'badpass', 300)
      .then(expectError, function(err) {
        err.message.should.match(/needs unlock/);
      });
    });

    it('unlock', function() {
      nock('https://test.bitgo.com:443')
        .post('/api/v1/user/unlock', {"otp":"0000000","duration":600})
        .reply(200, {"session":{"client":"bitgo","user":"5461addd9b904dac1200003353061409","scope":["user_manage","openid","profile","wallet_create","wallet_manage_all","wallet_approve_all","wallet_spend_all","wallet_edit_all","wallet_view_all"],"expires":"2015-01-30T19:33:40.769Z","origin":"test.bitgo.com","unlock":{"time":"2015-01-30T18:56:40.961Z","expires":"2015-01-30T19:06:40.961Z","txCount":0,"txValue":0}}});

      return callRPC('unlock', '0000000')
      .then(function(result) {
        result.should.equal('Unlocked');
      });
    });

    it('walletpassphrase bad password', function() {
      nock('https://test.bitgo.com:443')
        .post('/api/v1/keychain/xpub661MyMwAqRbcEfREDmUVK3o5wekgo2kMd8P7tZK8zrDgB454cuVJsUN5XzzwmdFRwjooWmmj6oovEZLoa66iHMBqv9JurunU6qKuCvcpMDh', {})
        .reply(200, {"xpub":"xpub661MyMwAqRbcEfREDmUVK3o5wekgo2kMd8P7tZK8zrDgB454cuVJsUN5XzzwmdFRwjooWmmj6oovEZLoa66iHMBqv9JurunU6qKuCvcpMDh","encryptedXprv":"{\"iv\":\"HybAlQtv1zzR0SILC2+kXw\",\"v\":1,\"iter\":10000,\"ks\":256,\"ts\":64,\"mode\":\"ccm\",\"adata\":\"\",\"cipher\":\"aes\",\"salt\":\"uk4bOcugPhE\",\"ct\":\"gGgjX06ICgv1xwUjKDAJBBgDcTw2IpLaRhxbpbnIiqV5d078iVIdrkzR0NVJn/BALR67rYYzOt9f0v8tQuohpTxePi+WGHeGvXfUxNaq3765akpqnUdHpo9KHVztkCaK4WtwLu2zIW4oxkEGcQgHiF6Yr+QkquQ\"}","path":"m"});

      return callRPC('walletpassphrase', 'badpass', 300)
      .then(expectError, function(err) {
        err.message.should.match(/The wallet passphrase entered was incorrect/);
      });
    });

    it('walletpassphrase success', function() {
      nock('https://test.bitgo.com:443')
        .post('/api/v1/keychain/xpub661MyMwAqRbcEfREDmUVK3o5wekgo2kMd8P7tZK8zrDgB454cuVJsUN5XzzwmdFRwjooWmmj6oovEZLoa66iHMBqv9JurunU6qKuCvcpMDh', {})
        .reply(200, {"xpub":"xpub661MyMwAqRbcEfREDmUVK3o5wekgo2kMd8P7tZK8zrDgB454cuVJsUN5XzzwmdFRwjooWmmj6oovEZLoa66iHMBqv9JurunU6qKuCvcpMDh","encryptedXprv":"{\"iv\":\"HybAlQtv1zzR0SILC2+kXw\",\"v\":1,\"iter\":10000,\"ks\":256,\"ts\":64,\"mode\":\"ccm\",\"adata\":\"\",\"cipher\":\"aes\",\"salt\":\"uk4bOcugPhE\",\"ct\":\"gGgjX06ICgv1xwUjKDAJBBgDcTw2IpLaRhxbpbnIiqV5d078iVIdrkzR0NVJn/BALR67rYYzOt9f0v8tQuohpTxePi+WGHeGvXfUxNaq3765akpqnUdHpo9KHVztkCaK4WtwLu2zIW4oxkEGcQgHiF6Yr+QkquQ\"}","path":"m"});

      return callRPC('walletpassphrase', 'sE8zgeeCjoyKMgdjbMzn', 300)
      .then(function(result) {
        assert(result === null);
      });
    });

  });

  describe('Address generation', function(done) {

    before(function() {
      nock.cleanAll();

      // receive address creation
      nock('https://test.bitgo.com:443')
        .post('/api/v1/wallet/2N9VaC4SDRNNnEy6G8zLF8gnHgkY6LV9PsX/address/0', {"chain":0})
        .reply(200, {"address":"2N1wzRTkUSkZzDLawha1QZKw5z8smyADzHA","chain":0,"index":26,"path":"/0/26"});

      // receive address creation
      nock('https://test.bitgo.com:443')
        .post('/api/v1/wallet/2N9VaC4SDRNNnEy6G8zLF8gnHgkY6LV9PsX/address/1', {"chain":1})
        .reply(200, {"address":"2MwUPsS6b7tGKDe8ZXNTAhdrQkGmJgozDMg","chain":1,"index":70,"path":"/1/70"});
    });

    it('getnewaddress', function() {
      return callRPC('getnewaddress')
      .then(function(result) {
        result.should.equal('2N1wzRTkUSkZzDLawha1QZKw5z8smyADzHA');
      });
    });

    it('getrawchangeaddress', function() {
      return callRPC('getrawchangeaddress')
      .then(function(result) {
        result.should.equal('2MwUPsS6b7tGKDe8ZXNTAhdrQkGmJgozDMg');
      });
    });

  });

  describe('Wallet info', function(done) {

    before(function() {
      nock.cleanAll();

      // TODO: make this common (repeated at top)
      nock('https://test.bitgo.com:443')
        .persist()
        .get('/api/v1/wallet/2N9VaC4SDRNNnEy6G8zLF8gnHgkY6LV9PsX')
        .reply(200, {"id":"2N9VaC4SDRNNnEy6G8zLF8gnHgkY6LV9PsX","label":"Test Wallet 1","isActive":true,"type":"safehd","freeze":{"time":"2015-01-19T19:42:04.212Z","expires":"2015-01-19T19:42:14.212Z"},"adminCount":1,"private":{"keychains":[{"xpub":"xpub661MyMwAqRbcEfREDmUVK3o5wekgo2kMd8P7tZK8zrDgB454cuVJsUN5XzzwmdFRwjooWmmj6oovEZLoa66iHMBqv9JurunU6qKuCvcpMDh","path":"/0/0"},{"xpub":"xpub661MyMwAqRbcFSu5cKZMN8LdcTZ14ADiopVd6SpgCLhpENP2VXLZLcarfN1qwJYx8yuyp6QkmFWaYLk4LLDR5DMTWEMKb69UzhKXcxPP2XG","path":"/0/0"},{"xpub":"xpub661MyMwAqRbcGeVsWGCm1sagwUJS7AKJjW1GztdKx4wp1UP9xpNs5PKPqVF6xaX9jQX3Z2i6dT5oJycFEdthymPViwRAmrFggvASmbjWaeu","path":"/0/0"}]},"permissions":"admin,spend,view","admin":{},"spendingAccount":true,"confirmedBalance":71873015758,"balance":81873015758,"pendingApprovals":[]});

    });

    it('getinfo', function() {
      return callRPC('getinfo')
      .then(function(result) {
        result.token.should.equal(true);
        result.wallet.should.equal('2N9VaC4SDRNNnEy6G8zLF8gnHgkY6LV9PsX');
        result.keychain.should.equal(true);
        result.balance.should.equal(718.73015758);
      });
    });

    it('getwalletinfo', function() {
      return callRPC('getwalletinfo')
      .then(function(result) {
        result.walletversion.should.equal('bitgo');
        result.balance.should.equal(718.73015758);
        result.unconfirmedbalance.should.equal(100);
      });
    });

    it('getbalance', function() {
      return callRPC('getbalance')
      .then(function(result) {
        result.should.equal(718.73015758);
      });
    });

    it('getunconfirmedbalance', function() {
      return callRPC('getunconfirmedbalance')
      .then(function(result) {
        result.should.equal(100);
      });
    });

    it('listaccounts', function() {
      return callRPC('listaccounts')
      .then(function(result) {
        result.should.have.property('');
        result[''].should.equal(718.73015758);
      });
    });
  });

  describe('Unspents', function(done) {

    before(function() {
      nock.cleanAll();
      nock('https://test.bitgo.com:443')
        .persist()
        .get('/api/v1/wallet/2N9VaC4SDRNNnEy6G8zLF8gnHgkY6LV9PsX/unspents')
        .reply(200, {"unspents":[{"confirmations":1,"address":"2N2XYoQKXQGUXJUG7AvjA1LAGWzf65RcBHG","tx_hash":"fd426d37e56919485bec45c61043596781c09af0e9637998fcace7f59631c5ae","tx_output_n":0,"value":10000000000,"script":"a91465cf7dc1dc237ad59225140773994a747674e42387","redeemScript":"5221021971b4d7c5d919e2655134ac12daa755cd1d6a14996c5b272de24178f3649e952103f8bb35d209e20c1f64f9f2c5686efbcb212a504d3c5ee65e9623187c03009a9321036d051911592ef2a7a72bd53c767d1e57f260c7627a8115d6204d9f33c7dbcc7b53ae","chainPath":"/0/27"},{"confirmations":0,"address":"2N8BJoXnpt9ByzxbxZY5ePrps1vbSmLG6M9","tx_hash":"ed426d37e56919485bec45c61043596781c09af0e9637998fcace7f59631c5ae","tx_output_n":1,"value":71873005758,"script":"a914a3cc3df0570bc12afa1fc2202bb6d6e366c1086787","redeemScript":"522102907b7674fad76d9fcfd95914f6ef5bfbb4accd1c27d050451fffd47eca9748b621027b5afd6ad827932a3a541d44e36d596d46cd23f309625739b2a9563f96fae6762102d990d4984d7680242680bc86c1c890fb6a027f30057e5e0f0eeeaed5f6f90bd753ae","chainPath":"/1/72"}],"pendingTransactions":false});
    });

    it('listunspent', function() {
      return callRPC('listunspent')
      .then(function(result) {
        result.should.have.length(1);
        var u = result[0];
        u.txid.should.equal('fd426d37e56919485bec45c61043596781c09af0e9637998fcace7f59631c5ae');
        u.vout.should.equal(0);
        u.address.should.equal('2N2XYoQKXQGUXJUG7AvjA1LAGWzf65RcBHG');
        u.account.should.equal('');
        u.scriptPubKey.should.equal('a91465cf7dc1dc237ad59225140773994a747674e42387');
        u.redeemScript.should.equal('5221021971b4d7c5d919e2655134ac12daa755cd1d6a14996c5b272de24178f3649e952103f8bb35d209e20c1f64f9f2c5686efbcb212a504d3c5ee65e9623187c03009a9321036d051911592ef2a7a72bd53c767d1e57f260c7627a8115d6204d9f33c7dbcc7b53ae');
        u.amount.should.equal(100);
        u.satoshis.should.equal(10000000000);
        u.confirmations.should.equal(1);
      });
    });

    it('listunspent, min-confirms 0', function() {
      return callRPC('listunspent', 0)
      .then(function(result) {
        result.should.have.length(2);
      });
    });

    it('listunspent, min-confirms 0, max-confirms 0', function() {
      return callRPC('listunspent', 0, 0)
      .then(function(result) {
        result.should.have.length(1);
        var u = result[0];
        u.txid.should.equal('ed426d37e56919485bec45c61043596781c09af0e9637998fcace7f59631c5ae');
      });
    });

  });

  describe('List transactions', function(done) {

    before(function() {
      nock.cleanAll();
      nock('https://test.bitgo.com:443')
        .persist()
        .get('/api/v1/wallet/2N9VaC4SDRNNnEy6G8zLF8gnHgkY6LV9PsX/tx?limit=500')
        .reply(200, ["1f8b0800000000000203ed9d697762c7b2a6ff4b7db67be53ce81b33cdb4408004f4ea0f3902e2308819ee3affbd23e5630bc9a80ab0745dee755d76b94a25edd2de3cbcf1464664e47f7d5b2fcd6c65dc7a3c9fadbeddfd9ffffa36f6dfeebe7912a5b55c30144374dc581e893491324584a356322928755479a12842d831492c268206ec358e527dfbe59b37eb00572208f35f11f915890ec17748de71f4bf104203f88c18e01330fc06fdf26dbe592f36ebdfbe832dfce6db1d7cd03837dfccd6e92a0d8d7bc7eebeb66c4f62be6eeeddae350a3a6f36a3417dd49def4b4bb8e0d6fc6bf3fb257ffbe7dfbffc7e39fce672f57dec338e1783fe484daa857ac9c68748779967c268d8b9fa43ebf5724208ae94e692ab5fbe8d57f5f10c3eb85e6ec22fdfdcc88c672fd77ef9d5ff9ef9b0ff76a7f9bfffef2fdfc26cbd1c87dfeee8cd8d3c981c6be7ef1b8d59e1204aea582baae1ac3c9cf445ed413757bdd7bff9d7dfee04ff7e279ff03ce01b73f3591c2fa7e63f2fb92498b25fbe2dc2cc8f67c36f77d1fc6b05b766ff35779391598de06ffbfdab8dd24e11153856812286b58a4a591d6d348822813477c651665c50dca5cfe2400c331cbe9551180f47f09d5342b054e9665e3803a82c6528d01810b1c42327acc7420b8cb4e2de111998c28e0acf74c0d163838917d4c333b1f04bfcf99c65a6d5ea94f426c762a3b0b4b8be8b2b9ed9ae577c942bb9fbee7e7c15678d4ca385b78545b34cf0d4dd875e2b5f6b3e148f6260f866f6240a0faf97e32f9ca92b3893ff0d9cddf83c7e32cea896ca198eb0c09170e534c61a444c7a45103714644c32eba38f8a6989390345d31e2b6b04275a1a7f9e3374c7e41dd3b77056df648fc5417f723898ecfc781c11c36335b3d8b58ebbdaa133aa6ec5b9e7fa216642b8f01c426bdabbf7033153d92675f55e76d468d856e6913756af5753f06034ffedbbbc8832f2a9949d83ecc687719e317e19639e82a068c7b0d11cb8408e09eca236c604ce9de7d444129d205e618d8d62123e87624ede33265fb54c236a191005d7d5581b8d18475c732d50608459eabd032d231c734c559098d2e88912247a1ab8a59fcfd87a9079ae3cd6b2b9e9faa9df928f71ed7a7d50d1fa5361abb685fbc1558c65e6d3075163c7716d1f7b4fbdf6a4e466b36967f6bcae57fba5f1289e844ccd18d2e20a29c35f0fd96d4fe327830c1e2b5c298674498481066641a5ac3752e174adc849b4c8c165b40311e5464909af84942e805da3e2d3216b14981db4c7ebee7e7e5f2b0e59573c97274fcb5cefb191d9b6b2f939bf0a325d696632b5d96ad35e9526931dbf9fc7c75cefb9b87b782c05d71ced4f2053ece5695c0e19fd1e6437dfc72790fa9341164d14467a6621cc72d02bc705c55159cba40d116b8684608a394a30435cd8a0204446891c2206336ccf40463b88dd617187d94d90e5b2eb3d5d8d16b879a0cb798f854eaf87fd40066be678517e3ab5513f424c351fe661e6448e97da3bdec9ef4a4af63b0f95d62e2adc63f4c439eb142bc515b1127d8fb01b6fe256bef8f7e8621a5d46577aed8da0ce48298d66117c11d8076e24d3514683b98c982ba2c136214a228d9673821d7e43175684fc4117d6440bc2a214c1222b540075f218aea2b5560a430ec93166f0075445123c02f30737c222d714fe409ff362b883f05d52317a135d74221fdbddc5341e7067b87d2a8f372d915f65f4be5d1c75b3b5fd555eacbedbcaf85c50ed7e9f1cf3448cb753fac8c9a155af156a7ad2a2277152a22461f2720953facbe3e48d4fe30c6494087c1964e0b4690822444139b87fa414531419268024c8f92867c6322ab86751600fa91f7c2448f6d6f063c4f11f90a964c5b4738205cb34135c7b63580c84b198c4cfc3272324c0dc6b0a1f8f3c5a2bb1e1d6058ce16f7e0f19fe95a20e217714dfd11b216bcfb15de9b8a9850cad2f57d952733a31fd7aaff4d89ae1f263e9f5b1a67bf9be86158693466de0ba10e437ab7cb133e08ef563cc3d66e4f09e96ea27cb171227c6ae482b15fb2cc6d27d9c47ec9667718e30852e4d29c123598d29e15c191422f32e7ac90138e911300539a4b0364642e04f21a60aee2cb082de1086387a4d292563040704bc10a2a3d39178169c84d492c2850d089c929a28195d40cac908264c41540682233027cdcf4d587db38c36a7d9633733191c375b512293fb21cd759f2be586dcb275ef344a0aa9e5e55152f1ff01ec02c028b69221f0f55860a141c90c450c2e0171d0d920144a8b6798186589640e6c1e775448e70d8d4a69153f020c0360e426c058ed78d876045beb72af6c1abdda437d336cb0e32113e7bad53a983391e143096393bd781a916367dd160a1f4d35a3d7a439d778428a8a1d62e6f562e4cf17236f2fc617daf6726c31af142c7f6a38bb21d9fda611da33f26c0bebc5fc84d6b498abaea0f5d3d63fe84711f7d647f1975f9bf3c45f9877109bb284c89471802a0a5268ed38406da48b107d31525aca1001764b21c2522791922cbe27fe35ef486f14c820e0c5d1de9a80b00c2470afe12dc3b174d651ce39e3c92006a288e33c80d2464bc051420ac4cf138fef38108fbf5a5231fe51d0ce80156996aad56ca1e8bb6bb20a9dd17c3e75f7ac7fcfdb0bbba99e066d29b0bea2e6a0d0a71943fcd735f5f5599c274c5c4618478e326a8c4012a72561892055888e40d495c1fba8444cc8d1c89908cac1673b10de97d5da3784893f0813dc58aac053f2001a60e0528c521991b28a41e642a3f312071cb9c7d6421602b8c115933785d7431af1731356df86997e72d979b76cf043eb7ea02b07358bb1fdbc53bbeaa0552f9cc8a00219d497cba0d4ff03d8058005cf88f054062e34d64c711b1ce34e40024b79b280d8216d220a1a8c01e4bbd1191724c47441b1e3269c050ca93b4eeff86d4b27a4d79fb7aabd56a9dbab744b32b37dcae05aa6f4788c82dfbb6cb974b680f30114e82d14447ebcca92adcc7bb3c55a670fc7bddd0ffa3c34978b15dedaf6b45612757d2a764a426cbc5cece4e79624ce31c4d0a5c52a1ce15524543a61930913d8387064cc722cc091294169b0100a0578e44880052b884210ccde32444e8a551aec9c0acc30c67cb002a58a8d55409555010788addcf1e8a9897015c385e714fb80e07f9c690752f6678688ee10fac2d04dc6afbe2b3d764a83192f94f3abc1bc5fca129bcff99c65bbdac32a3f50856b8c5fae7fac168f6cd3dad61e3255aef7b9facc2c3bf9ae29986391b6d949adea850c7c3919e2534ba267cb08373d8bb384697de102af07ed8067c0853310b340ac18c814b121f868ad8e284529a968002082f2c64a9e7207f28e304c5fc3a091146094269540adf024d5442368166138680612a5bc30082ecf904bb90d38afe03128a251cc90709e307447d3bf7f3f6105fd342cf2cebc2576192c1f3aeaf0b0a83c6ffd6c537fa86e0f557b4a9806c2c81584897f0e6160602e232c68eb4c101c625dd49e6b0b1926365ed168b491447301626324e2d1596a3065914160d4ef9257ac4f1a3b2812dea54018a8739c1109aa45b95729c846efe08b638000e8107c0a2560b6b8a152452aa2b7f0a96708a31d0c7871f05a37c5c1fc02cb3acb2f5ceccae1eefe49ed478be752b35596fb878715cfe4ae5ae43df696c5495caa5973b45d5740879ff9310ef7c387657f979f8df3f9d3823b07c4d81588b1af5fe4bded699c812c55192eac24500f0838888990b959101e02999c4528e2a062f0d6f364b818925e126282f4c1610471ed1432ac297e5de475491ba5b106bc96a242689e4a118032a7d458f870202852464039697060c20c2700309830c80228139f0f191653b1ab93dc7852bff759d7a9f5e27058211dc3ecb6ef36a5e29f4b3c1fcb989cd79f1622877da9c68ae5052fad483fb0fda4b6c6996eb9b53f9e328680317a05639fb606c73f42eca667f1b311162827e98a204b4ec8b48ac1284ea4b140a53552394720d41a8d030b1c41a648828854518d3448da59c210bda3e28ef3af0e943fac84f2ed51ef8ebbce72b88fdd9eaa093cdcedcd68566eec1e74eba970da35443148fa155504413f11b0bf1a26f977f1a217e2152d812c1052bbc0553404be17ed09f87af0e84a0416e1cfd3926d745e017ae0cb0d43168bf8162fa25ef1d2211204092303e366e173835331595e502f263cc68e5264210d00dc7404e00c0468ae039608525c8fcef93092040cb13b7a5bb608df75bbbfdde07d2bb45bb3c5803d341e06a2e3eefbee793277667e055e42d49f32711d1f8f76dede6597a34af9d03c2e17db512fbb76b578d27003b7784d05417c3701bcf11ebea2cece312297c1a5236404808fb25881838f9a71072f3b33818233c360c49c249e1382490a7b0818108804fd0e2e8c5eeb07cc6b481ab085fc4144f07548336035029b9679ab83e3828392111a987252a6dc119900b90342d2ea33da8545aa1f707447d0577771fcd0e4d7376ed0ca2ddbaccd57f9fdf4a9e59b3db72e179a612dfc782856f76fc40ba2e315aba9027f521f07feac46a18f0913eac24e0eca4570de59e23d258e6a152386b4522b2230e1e0ea43404168efbda1","1e4b1949c45845f9863025e86b2787a03840e813d645acb197162222718483ec819197d4400a6914890089d134f10cfe2b80e5b7ca5b43f179c2f01d527784ff0469e42cb64ca3d46ad9fe5475e934ac69bb5c8cb8726cb9ecb0414e0c0c4bbd2b97eb17d7ff98241214e24205c360801478254f1017227211b5955e5866b9864ccf6227437a4c5e19ef280245a38480e6bde38b9c2818980e4e0c88a84669a103042d84b48eea9903f746b96218886224ad830067dc580dd2e6784056454dcff285f01d26b72d844d97dbd63d61f35028e3e373a3170af7858eb8aff9b869b63bb21faad744c7fcd11debc5876e2b6b494b72f650d39dcc70b2ad30793feadf6f4ef58b4850e5cbf58babaf355f373d8873704975e10ac5cb3fcc0aab52859d382da2724a05e10d365a1b2001439a6d254a6bacdc04941a2ecc3bb838795da17052a3c884b45468055112940d058219e4869611e79883286b050227af3852a0691028816f1f8262ce9c2936629ec48ba13b266e806b86bbeb163e84f18ecb81dd0f2bdbd9ac2ae71d12869b7bfed49d35ae5a6475d37c93cdf551cfee67a3a61cb47ccd356d2bf7d0dae6797679e2bd52dfdd158520cebe58bb6e7b10e7e852979aafdfe8022131d630ee415f04a489c43a84d54be345d2aa881816c412704a1abb007eec5d68e427e68b1948110c843c14c172511ad28a1a443e160d63523247a2a5d1638a7d6a394bbdb63868e11537f03efff38613a08b26f3c5e86d744d8fb3d1c1fb4a876462a9cc26199f593d667ba4385e9352c68c279bab7a3728c995d68b47160e193991bbd270395af6f6bcaaf6c736cde6caa7da4509c5572ce173fac57cddf628cef025905257f08595027a9c5401234c5f7631f9e8289828d02be0450722012c6b25d1928093626f17261444cb3ff8b269b91f3ba384c64884289547e0e581596340bd2c862fa7969997ae6d0e6aa65ca05e3125304028f079be2073a47758bde18b5eba41f3f257465e5765fc4e4745aeb17d62f461db7814f5e3b0d3ce33de9a4ec6eb6ad3af6db17fb2d0cf507aacbfbf949f60ed7f85b731fdcbe65e7e9420dc7c6b7fa2f4e22a8066d45b9e04c801a15a33c2715a36855088ad8846eae88dc7c478eb2da48bca612c3c316f293dad0280df733202f7a9e38a5283a8a4d442d2e0954d8b279a2088a904b4170415e2b892d6427eab0464c106737a9652307054ddb87c76cd0bccc88f7530ec47c761cecdfab9c6fe8873ed696627456d2bcae5e95c6dbb8fa73ac848b2b397eb20f9245019f98c24f4e52a1f66a1825c5a2e0f087b2220674c48a5bd9b2064287a145c48a68b47194c0c4a24b5a290b243d6a0ecbb723956e8740f315c4304ee10414c4b8e8d836c13223849898250a08f364032a0bc361c4854e01d533ba685af81f4349ce99344ba83c0c5913b226f6bb9c0d9351f3cb5863c3c566aa5cd70d827f938291ff6a366d59861f68a2a40fd807bcbb91f572a3494ab935cb17f7cb04d9ded957d93762a3b5a39610c8c2a2557ac73b0efe6a1b7dec65faf249c234ce90b9b7ab432322d9522e25d6434951589562c38031a8921f2c6088203d7d3902f00252a7d9ea56fcae55882d77b6df5f638c0858533c28454a19490eb5348415dda88903203275261dcf3480564a3c16a2691b64034a7e0033f9f30dc5cd79bb8b86d56f63d35ee6ed676b2bf7fb8cf29b177fb5014a36b08dbdebbe6743278ea916cae2a89ef148e74f78c4d8b1e9bd2f543e394300c2a76452d93a3afaf33ddf22c7e32c298b60e540e2224174ac8089947a0282dc61961a9d6012225f3524ac72c8b0ee44fc0e73ad041261517eef3092be430d5e30add75eaa19d63a5f9aa5ae84f17d3d21cccc6245b6c5c53c92c340f92647c6d32ecb87dbf549890dcb25f1ee44ac5ce72bfec0f272784a55882afa864f2efaed5de7a1bffdf69184447637c4c1d3fca43b484c4c0a51d9b02be1ac1c7b9d2101883b34c4478f8103ec1de11903d482e140eea0c61eaa51a20efd04db5f2fa1e7797fd9dea151e0b4aee66abb8af2ffb313c3eadb28bc75ca6d3b9a61ab0ad970a85637637d9769fb7a3eabe6a9f5875d25a9427f76ebb5ffa934d9de045afd8d2c9d4972fd5def420cee1a5d135f928d186588e92e396d86a01a61b08c5f06a4b2e42da4da2b892d410e4ac40926a87dee1855ef3d1183c8204961ba122b0c8a37082a160c0d92b06bce9804cb0d4a4ee34c748a2cf4a0f7ecd1a0ef9063b8b17d67784dda1b7f9a8d6847c6e3a8a3f291bcd950ea3a7de66c0f6b3318ffde106b7769351abcff6f9ceb651e367b6715cd8664b3fd8f8327dc6854e4b54059b4c3afe90e5dd88d5fd70e30a9391c00c24e1e42ec5cb329ffc2c9ee959b59c3e0dc8bebfac39590ddb56e837a68f5d5ed387a7be586db2edfcc09fbc233e484c6ebeab3fbf21d8857b5958a4117b2b98e198091f9123361ae2057e599d231863af59f0412a27a8705c328d257e9b95482a5ef7b2485053e605e2c109a42343262dc328b0865c838a6be9d25b00121fc88314fcf59e6304e989d398456fe9876f08046f885b22fa352fcc8f13df3cdd94cadd36159d633b5f99324bcbddcaa058ecf632d5c372bfdf9eca2d78657a45f1827d5a0f2ff96001f0a647719eaf0be339c691a8b4f0a190331ee00a8e78e51872de69ab88e416a9a03ce790433890381563c42f14bce14b9c4c34d290d36209497364029934e941720e0930002a0de1002da269c73ef0e3244e95b3347206ccbba5eec5299ce14bdd31e0ebed02333c02293f5771c9a728ee743c5ef69bf35533d7cf769ab3e2beef5d65ba2baff4dadf2fabf3c1496aac5309927cd6d23239af5b377c3fef846f0321b13fc9776acfea382c98f553d957969beae30a881b65e8d3bbdd84df01535e06669af26128369431674004d3dc2ba58123e210159c45e38cb101d21017bd0a310dc41204fd49f8f86b2a436de060337d5020a34e29f00210e553a31d89f07f6aace00a739566d8c025bd36da47012e803b4923bb1c4c8a39d33f16be4523f66b71f3244ca3bc2b503d69b7787f78983ffaccb1b9e84dc3e95299a2f4e3d93457580af25b49ed62c23f87cb3ffeda775cddf2084e0b26fdee44b74bb9e3a6b8d40b21179b90d7fbb8e81f1ae12088386916fe155212cd18d7b7bf357efdebef0d7cfefdb92b94c2533b50ac6879b4ce2ffb9cf24ca7540ff3639c1fdb9bce8f2f316dd48ac55a755dcff6d8b016d68bee521c0795696d3ecd364aebb23877899fec1d0a69a5509c616e200279c4e07d19297c05c784eab47529cd5aa4c238458d4ae5038dc0a8308205e718dec567dfa188a7a18b37751d4eb74fdde15e8d733bfdb418648ea5c6a6fc18716fcb5b9bfea1ae1f27d7d426f1f3cab6f8b2c3d706ef8ec755fbe9b07cd8d5db6237accd2ab8d33eb1b057351db2afdef971db7338039704302edcc32d8c0657412485b7824b3b1c954ecdd2d15087c0a818812276e0b1d3cf0a1127ac65ea5dc7b424529c744c63e5bda412dec11e499bc2548c166b44d25a95a0360aa037f5ed7bb0c6243805baaf230ff4a5f9f03c5c2f133db1feea9e30c27e3ca04c94470b90c167b96af15da6dd9d0d72cd3ae507d7ef0f43e5f9b4f49dca5bf48ad237fdb4d68a971bf9ab7d61274fe32c64e2c2d506e5a5b6902e099926057382b9908683a409c204f68a31c87b10f73499626006396a91d7f11d64ec75b5213550a4fe8954244796a6c91bc183305a903e6153fb35a0c54914960153401e92409a0f11c4ce6a747e310bbd4cc17b57fdfe0ac82ed8f9b126054bf4a47f6c4fc739465663daeee67d27cedb8d7bb3793ad1308d054076455d917c5aef21e19f0119ff0164176e9284e0873c4a49930e11a7111f0005244292198d71c0a9d42888f2f0864c7bce14559c0be4f97bc85e374946ab15a4ff69ee30d290ebc710097c154e13aa2c314ab9a0694805379ad60802960a6e4606e42012072c3e822c2999f86ac87e2ffa7e678fe4aacb8bcb67a7f17d7ebe704cec773917a4c8970f9971de9c6c0b67570d0a209f96bec33dfc55bafe780c67d992176efc8014c52a8331e111c3fb2c182fb0708406e93d61f006d42e2d10819c999846091062592a03be67eb75e307e7f0f60632a96656a43630088c90fc6811914fdb4a50f052407ae4b9471aa7c965d2409acf29522c6a64fe56b67ebc1a7f28b2e266532c89d56376fdd42c64439d079729f47a83d5dae6e6c313fd4257c1f5cfd97dfb77e2e5ad75408fe63480d7175e440a69b9001fa6d274ebb432c9d2f637c6013c03060cbe380641b0076174ec5c0efe3225364d59247ff700cffab143dd5cb007bc6b579e9bbba7deb8b79f76779d5e66d83354154e6cb26618a2e315d5c4ef2f11fd44133cc1745fdadcaa8d0367154cd03e520c2fbda504dc36553878ac9cf30e49c6436a6d504800648143baf7b6ad4b82733aa95683a743c6816563283af07704aead038444fa325e51835ca168c09a01d59448ed38fc3619c0b485fc3c5e49bac87b8f7fd924f5feb846bab5c72dc199f6ae3aac3d87c3531fb2d83eab48bdcb9d9aa56bd61df1870b8fc7f17c51ad361e2a621a76cfc57a75d3edf9e85de39e2f4bdddaa47daa110a73fafdbec31baf773b591a9f5ddc58b56b8d28564c13d5ee3e3764f5491ef3e5f1a2651e5ab3ccb8327f33c54792d7fbfa139df4d2d19f3402e50a6cbc709483ab029e2c84bfe82302a1421c525299a6a044876ddacecbbd8a903eb83774a69ddfaf74a6fd255184d46898f66c3aadbdc4ce788529811cd73a82a4e45606210c0b8684800ca1827303a9098ee7e9147794bc8fad97085fb1948dc68987ccaef7909d6caa073d6850b96c55ee3bdb07b2e96f4ee7285e43a7fe00ce19e9d1c7566bb8dccaf848b3cdd2beb892319f19f437f9fb5133f77432425bcbdf762da1cf5a80d4e41c58377e4bef16ef1a8cd7069d2da6b54ed6db0753cdbadeea7e559fe5abfdd276543f5d4154fa7b91995e9a5420e2a81014a8e42aed0b90c1380c06cc47e22c689c03cfcfa8c136a4cc43882819fc44f43b384f920a2b44e03c401a0257603ad5c185c3319db1032198c900c1991001026a9502a9b40672dae03836d804c43e809325e944fa4be1d49f01e774bf6e10d27958dedf57b6629aa57c2859c747953d3e3e37f272527bb32718fdc6d367c1a9cfc3b91b0cb2935da55dcb56aa23ddf058d0dabab8282cf6a5eebeda3d9ea6241c72217286ce9befebcf704a71e97674659174106db10ac2b808e1d673eb19f095762c79ab344005a11e4b08d5001dd046157907277d5dbb234824cde4082432a6c5612495f5ca1bcd03047aa422a30c7eadb18518843501ef685d080c0c6b2a6c9e8113bfc0c9c057dd36b465a78aec50a96756ddf58e2dfc708047b5fe6170249ddc4e67dbf92b32de5ca1b63834db60189bcdfb956e06450a99ce7494b9dfd1756487dc1bdb08def98aa30508fee2a4f7a62771062f852fae3b004a5a2b26c13152067ca523091064a4a9e44035bceecaca347f364dd210017e48f026feedaa1d2432af75070e1ac61cf817aac0240646ac93da4a873c49dbdb3904f1b44d3428903b2118a43ad2a66ec008a64028a33e1faf9cd9914eb7fdec59bb5818962ab5a5e8d61dddefa40e839dce8d2fc7abbe5f97167e3b6fb572b96968e5f9a4b66a568a956d57d5f6a321f64f6ff0","e2945ed1454bbebf17e0b6bbf8cb84fe6478a5017bdc7ba79d964e2b6e15b25a0ab083c460c856343602f043a91f07a7598c4410a5200c7b47b412fe3c5e69eee2ad49ef670ed3c8d87576d02935f3f3fcd3a4b9e77d3e7abc8fddc1f8b9bf9997f0e08d7a119a0a7e97e385fe21e334002f75e989024c3985a31521a8344857480a91ca046e82a2a96ca089b5297cf1188d85a0ce38c658bfc7ebb5e6a04d340cae648132c498f0043303193038390034822dc4e9ac4465a24f0761c0672b030073252d87bfe32d5eec574c7ea5b8936671f33b267f82711af7035773cbae9ff6d6dd901d66d7da0ecb22b20c2e3fd2ca3efb862f0536e572beb0fec78cd350845e384e43529dcec734d4206465eac9d6dc594920d55402074cbd63ced8d40f412c75d1425c4b65fab78441eafb2a609016686007120203de1f14306809a205c297a671f8a08cd03a0845244dfdde60cc587090330b26a354fc2c6148dd617e47c5df3e6c2ab3c9b28735ed8e3b6cf3d038749afb7bc5bb9998d734379fe417d553c0280076c5b029acfe21c3a6146197a69e2c201992abb6d8b1c07504cfe083730843e8c21ae3889d8f51788fa3f412328aa80879e7ee91784d3d9176023b143810644048c1c85b483791b3169eb68064d3484e21f12494a5162d0f1f25c6114421b7a0f2bc80a5765472c76fb35f57ccbdc73fc2abd46be1e146b5e8331d0ed578f4acfbade553b55278a875dba5c5833fc58b6bc4ae2899e2cf1c79f0574f00c0dfc54b5c68bf4cdae28b68c41020754c561c38e3c212eeb850321d8d435e1a3402161e6228265844cac53bbcd8abfdb21c32cf34f9d80796940fa4cf2191ce8a8a3242d0240c6082c049c0e51319354addd6a0694e491389403f375ec5eeb81df2b9e372240bfbd1343f73f87ea3d4a0559c98dd3abf7fa35e5c217645db07feee2cc61befe22f13fab3e195e62f06c30c48964fbdcc1230499d6a912110461238d21ca50a0642d447662d9542a4c377bcc52a8abf152ff2c37efa7d75688a7d5adc0779a83ced8bebb63e4eabb3f920960ff2c14ddfe0050fe68a7e7a2c3e092ff20978919f14af488844463ae64d44e0a750aabf86b4a84b48e432a61e49c6d2904694862223a20387a84cd00b8cef464d7d0a5ed7d862427f34e933544c67be6cd86a635018cd42e571d0572ddbdb15bbedcdd364787a3e0e633479dbcbf9fabc99eb701f67c3e34dcfe227234c401e4a0d6388a4e36d749a97a602a0668507b34f154e23da894ed33628920c7c3fa55e58415c1a09a93f70f7f42eedc1c45f2d603facc91f1e164359586d9e17d9e7a81eab8d6711487b323c9a5c4d6ed62ffb47ff004c20ceae58fdc2e49304eccb9727c8a585a58412381f885882710a961b7445a4057deab0d7861891f64c38e5783afed01ba2b010fcedc12309af57778f8503b71e9d85348007ca8896ce232f198b187bcb502434eded35f0514c84504e1080d7581e5804127f06bc3eeef808ab1a656e37ab2f33a3e96c1e8bcdddd8b7dacb69b770bfad161a6fe94a67ad5c4ed7270e2afeabde9e7f57bafe36b6980c012c7b0405f39c1b230383ac1133aa71e0220dc80e0454cdc0cf424a503508934e0aa2844f47d2898fd84ac1f1cb27c9fe7833a3388cbb0fe59e5cf1a3ab8fd7653fa9cff78b56bdd029e8357f50ec0d5de904b22be8faac49b29f32c4877c7fe94b5eb8f41520688918499a6e4c28714c50aea9f411474325a0c75c248e184ba34b6db251c4747449784fd8ebd297523e1dee4a2876d141fa445301ce841034a641798a9535383511a5d917241dd84153434750815b2ed907ea8513618cfdfd8babab816ad667c58d39cab2db666badbda98e78399fe96e36a5dd7e5c3e254c0161572cde63f40f5a5cbdb4b6ad71c4261825228428a48d30312a04699df33810c8046d604c46c39dd3917312bd03ede1ea1d6127b56d193c383425d23002aa54449ac1776a582a91d35431f24c803ba3e0f452cfb7323c75e1a6ed2a5c09718eb0346a5da76d89ec2738f28656dbd5e6e8795a6e97bdd643f91c7a6bbb1f1f6a3af3f4184ac3fa29611a08bb62f9fe9f33ac18f2b20beb4344a601fdc2e8d4d8409949232eb40e1485d46086b5b0d1a6f9d7311a028ca405505035f156c23851271319c14f61c80eb8000b9f4e38575122ab38c8228449015f2c4910405a3a5e90c6742218f10ef206ec8934e44c90c4aa83f41d857ffffe61d8f5552fe6dcfea1b46b9b0c9916b3d95ceec966f699ce3cb75eefee9fede909abe944aa6b4e9cfee700c62f2d0f459ebc0f28b90f5649a69003a7a50df86d0e6071a582f7c1109f56f1b1d30e9c3ad53abe1db1c2e449798842cc0b8a79ebd3643c67834ecd13126313b524ca33e3412dad06b9249a726031a499f7d182d10bc69d4920114ec7c2517ee3d995f5836e6e26ad5c9199c7e3fdc24ec6c7955d9a4ef3c8bb0b591c3b768d82e517d545b15899f7e69daccef345d3144af372aff2ac5cfd38f5fbd33d033cadae5eb180cfbe1cb09b1ec59f014b8db017b67513ac08b7f09ff1016be3b1625130501309e69c43aa6720c5c3293a1a91863e716b0143f7b6fe88f5c9cc6208ac81ba34aa389521d3447585b0b0160c3ed2d273249d01036c82408240fc3538b585a59352634c4d9b9f0fd8eeb92ef7bb19cbf59dec1965828f4f99d9c43e08d7a9cf3ae1f9aa0a377d685487fe21e37d6180b52a2c5acd43cb1f1787b9f3c3d2b0fa1eb06b86167fbd82ddf2287e32c0d2cc1385ac084a190761356d63915404a1b837c24783140567e2d3d936323887258bd42a1aa30d6926dca703d6a0f345be71acced832bb29765b6d95ad1e1fcb949bd2e13015d3fa9f8f41fbb8ff6ba00bbcbe2a375636238ff5d6b8f1b43f3ed3e164f2d0280dfbcbdc5bbcd2c08bcbcf23f93cbcce9fbc7bfd63f8d9d0629ca57ab807f5f248c5001135a4e321802f974e15178c86b4e9098c1de40a5ea2e802e669a9cc7b1ac3cfa05d1fa3b58da3fcf830a1f3d5e1703fa199fdae631f96e5e3f3ee498daad5a7b7687176c5eabdfc5ab46e790c3f195a60dfac21462a0b7e4ba5ad7269eaa24e474ff0206c3aeb8678ea522ea9c1722109cae6d2e97096622046bf470b2763ff9f495ef4cb379bfff824cbd9f338968fca14c6a2380935bb1e4e87eab8b4ca4f0ae3d578710a57f25c57acadd22f9ee475e3a3380318275a5e33cbdf6286456a72488d3316323e78f985c1c805c7d311219210970ea8893612124c546f00431a617e72562a7c65082e488948ead0872ba8d4dec3522d1298815cd4e874fcbcd2e97258a1f0db7e3dea7940ee2c6004a5b322e84dd30c6e199ef897a72716e6e34aa73c1e6797bb85bf5f0fe7bdecbeff94992e8683239ee4baa77b84fe7360c9674d4dfa68e1eb966fe9763e7ffd11a0172e6d08cb011fc114843a630316587aa08a6229d220a0745eb948ab0e8a0b96fa7318f31026857f0fe8ebd246ea64d5e97c5f4b290a927ba90348a062d4ab0899029624ad79a44987698a9780ec5450091902498501aace00fa32c69f893b76e376e2fb2c3f96caa5a7ce9867bbf558ac0c72aab3ac4efb99da7250dc3d9eb6bcfffee3e3e2656eb95e2d17dd49b14ac77edc7e3844e35da1ba3a342b99c756419c4a602a5c5ed3baff791b43e007fdfd3efefac338c398b89831c80b79dafce670da4b6c9cf54242a843ce381e0873c12bcf880e5e701614f6694fd1fb03a3913a652c8d4324de13095c7248400307350c043055d2306a0053a282221e3380da49af21fdf41a5c9de152bb732248d27c62c2eeb8fadba36c03ef1695d5b6ecf548ae0b23d939e61acb7bf69c1b0fb2e2a1325f744ea5445c779a1cfec7445910a00b8f89007b6611551123a223f55408150de483a901d64aab19885a4c47f85a9d8e74081c2830c2be290020a94fce22410018b8416db592c9233a303308348b094ad3d971a95c0a4849c6581a18e0525c4f33b2834e8361a93d0f184d36eeb612d3e71600f23d966de6437edfe6d5fba7d5d3b6db286e6bcf8565be1d06ad11ef9e02a6ae3bf20bfd53d6671360172a1807e7c6d3222a64168a324939512942820513517a0f82e50d8388e6454cba165d8a6fd6bd07ec55c15e8ee92542d9940e2821298d69ce0697d6694a53964023445fcab5b01a818639e0d0f074b809e4a2ca7ca460a9c244ffdb6cdc274c65ed4cbabbc67db63f9e6dba995a1f172a8571a9ccd661b65d7527a593a3e724f8102585f80a3377663cebe5dfd8efb31bf17740bbb01d2344cc99c51ca5e3b7086336a4331e204b14e9d437c81e2173f008340878d4182c7d48dd3911bf07ed25975aadcdf2b7d7f93f779566b0ade76bf3aff4cb7fff3f19938b64cfa50000"],
        { 'access-control-allow-headers': 'content-type, authorization',
          'content-encoding': 'gzip',
          'content-type': 'application/json; charset=utf-8',
          vary: 'Accept-Encoding',
          'transfer-encoding': 'chunked'
        });

      nock('https://test.bitgo.com:443')
        .persist()
        .get('/api/v1/wallet/2N9VaC4SDRNNnEy6G8zLF8gnHgkY6LV9PsX/tx?limit=500&skip=10')
        .reply(200, {"transactions": [], count: 0});
    });

    it('listtransactions', function() {
      return callRPC('listtransactions')
      .then(function(result) {
        result.should.eql(results.txList1);
      });
    });

    it('listtransactions count=20', function() {
      return callRPC('listtransactions', "", 20)
      .then(function(result) {
        result.should.eql(results.txList2);
      });
    });

    it('listtransactions count=5 skip=5', function() {
      return callRPC('listtransactions', "", 5, 5)
      .then(function(result) {
        result.should.eql(results.txList3);
      });
    });
  });

  describe('Get transaction', function(done) {

    before(function() {
      nock.cleanAll();
      nock('https://test.bitgo.com:443')
      .get('/api/v1/wallet/2N9VaC4SDRNNnEy6G8zLF8gnHgkY6LV9PsX/tx/c1cdd3653d6e7e2ce43e88d3a44f95d550f1fa800c25139d60125c668e563dfe')
      .reply(200, ["1f8b0800000000000203ad935d6f5b370c86ffcbb976078a22f5e1bb65dd52aceb902d03ba66d8052591b69bc44efdd1b428f2dfcbd3a4e8b6eb090738c712f9f8e52bf2d3b419d372eaa18f1113c791342b76a5a8a58c284456793083059302d09143ac234140ee2915e51487e9b498861cd54908819f013e0be58f004baacb80df01c09547987a8033e6b59876a7e3dde97898967f7d9adefb8f69e99bd2fbeeb43dce9c5f319c1df9eaed6f2bd6d73fff727e5aaddee073bb7ef1f1c3fae2a5c8eacc91efe5e6e4d0101fb10f8bafacf06fd6f3f2e77e75f9eafc777c798b173b79d77fbabcbb5cf39bfa63effbfdfdc76fac92f051e0e6f06ab3f58de3fea40f7f2f26dd1ef71b7d14fc3fe8fc27e28ccff1ededbbcbc3fd75fe81305f6d5e9cee4fdf1fc3f9c5815febb97c433cc3f0c470497db7b5cdfe568e9bddd685312fa63bdd8ecd76352d4d6e0eba98d6fac1ff02c2a3ed10940d861204a38a896ae2aedca3dfbc24ff6e201c39110ff0f39c598d2bc614a40a6473023e826cd898df9423100122a408a59b884554cb586a684e4bc295aa7932a79c7aadd625b2590ec34f2b71699453c25c6646464fa6e2611462eb8503428d7daeb92669adfb2601341b1db2e4d6cc0b08aa06da0c9b42a0e27ad8595e71cf025e531709d65a224bd56a217f2008d030938421c6a1ae331946514ba8c18b0b23bb51b3a2d8874a6c5c214a66502de0568dd0ba4b0f146370114544d83468ac0c236a9792731d82e28a7aaa3cebf1c8514c42072f66be07746b34923b6e86094d0d59213214322ea571034c3088b516df485f182e2d153463d511038dd854a80f40f755b955a8d547971ab8b2227de40ed84c69845c03aa33104b278b5c889a7673eba56a6f25d55247e48183dd3b1065e69c912aa12322d76e3ef77ea93c1bf5b400092a8ea7aef8d262596a208f0ca53745d261b517f40eb268dd4df6b3d806958cadb94f0a25fba5fd277f48d0c25843d53cdcc9ea6d386a16b7888d8ae4d8dc5af1fcaf793e23ed66d7afd77258cf2dffb48c53e7114d737656556c442a7e30c0bb30a91b5a804af3aba328a3e464dc460ad33c3b9bd5da27346224e087cf008362ad2c050000","ca81eebe6173470f1de992d03ec508831fb18f61741902af38ba68c5ff2e8c98b60efc0a1a1a174ac8681d0a145296f74658aa7580c6c6bc94d231cba203231370ad0347635271e13e1fa34a19533d69d05def3674cbacb65c372bc97c35af2d211acc4ad5f607306a573a7b49ae7d6b36eab93ca95566a49c26f561b956eda5799a8c66271849d8304c3f86d1a5c5febfb9113433637c3410249587e60691dc49e49080bb117ccf95863e169c6522c20e43b783c845c0c020d62b1cd4198c548f90229745842fc1e836c7fd34d9a941e5b1a2e46eb18ef96d9ac4f0385d97568fe5eb5eef7957f1db6e745bab540ea5dd6cdbffb61d37f3a69db2e6ec6e559fddbb6d9efaf40423adc499d8ff4956847f6245972df71c4392bf8fa1a717d186588e8e515762ab05a45d29148623955c04c31d555c496a0872562049b543af1842ec0f8662f04807c28d501180e35138c1503010a91503a8744026586abc01c362e48898951e3294351c823e3bcb10d645c28ae8e5b8a735219f3bede18f0d7be5da7e3c1d6c862c5f4c784c461b7cb79b8def1296dff4b6ed16bf7e56266f289353e5f9375ce9dd89a660b359cfef4bbc1fb1ba1f6d5c65361698c1437c52b2d05aa36332fd1c36e9597b9b4f87244fd29693cdb0bd0b497bfed8e72dbd9f2662bd29756f86fe84ee9f04ff8b57f51a6e8dc9fbe0669146ecad608663267c448ed8688817d8c274e709c6d86b167c90ca092a1c974c6378025ec24d857c8e6b607fcc0bc48313484786ccf11f0b05a98c6bb05d2ddd1167182c60ce50f0f39e6304f1df69cca2b7f4a7702380fb923efb9173797b7abca19b5abddfa5a277e8de34e6ccd27abf31ac56fb83ebe63ecdf3eda93f424ca5e89f4b6be4bc455eb6e0b310bdb3cb621c893afe45a090331e080a8e78e51872de69ab88e416a9a03ce790d11d78928a31e2a7a37e01d17397853c068321963079462610f8ab877de430450285d2100e64226a348b0089935887c024a6c7706ca97beadf672052450610891710c10e48f9b916493e6291f3c9244d3acb75a79c947a9d45354fbc6bcc77f5b5cefc7dda5c0e4fc6484829b079f493f821e72de8827a5e79d8065a5532bbe9b5bea9c3a862b269dd37d24df3710d5c8dafe9f40461fa97f8b1f7e107add11a8a0d65cc19f033c7b4571a68210e51c15934ce181b20e7bbe8558846702208fa9387f1e75981dac021e2f9a0c0111d8cef5140f3c5282012e19d1a2bb8c25c05860d487a6db48f029a33779246f67efc28e64cbfed61ab764c5a713315a65ddf55a89e75ef7832da2f1ffdf5a1b31accc3e99f4a8ad29ffad7473a3d39f6977f2ae0fda1fe8a9e4b567a72fb21e9cf74b7563e6caaa95e09b9da841b9dc755b26f87bd20a27c021fa47ecd18d7973f005ffefe1380cf3f85f376ab5a6d35b3dbd2808d5a215bf553711836e6ade5bcd4ae6575f1b6c4ae520bd36ea058d1fa38bb49134ef975af761b9687b83c7437bd7312ff8ee710aa5867263de24b8e053dad080388d932335f61c214df7f05a50201f94b190000"], { 'access-control-allow-headers': 'content-type, authorization',
        'content-encoding': 'gzip',
        'content-type': 'application/json; charset=utf-8',
        vary: 'Accept-Encoding',
        'transfer-encoding': 'chunked'});

      nock('https://test.bitgo.com:443')
      .get('/api/v1/wallet/2N9VaC4SDRNNnEy6G8zLF8gnHgkY6LV9PsX/tx/a4dfeae89864f26a7e61c843aadf48c6d64b0758c16d0ba7b8823026ddbf0883')
      .reply(200, ["1f8b0800000000000203ad9551735c350c85ffcb3ea78c2d5bb694370a4c18289d76606829c3836d49c9a66d529add964ea7ff9d7309292dafe087ddbd77af8f8fa44fbaef777bdb9dee46b5f0e1a2d26a501bdd5b5e52cb18165556b35667ea2c2b374b73f429422551339b9144caee6467e3e050a294f95ea27b597ecae9b4ea69a62f524acff044381ec8695b27bbebe3e1d5f170b33bfdf5fdee0d2e76a7b839d6ba3e5e1d36998794ef1ff8d9e5e373f627df3d383b9e9fff425fc7f36fdffd71f1e8fb31ceef43f1cd7871dc348bfea5fae1e44e2b7faef5558fa7af84b2d39bb3cba7f1cb7eee1f5cf1cf67cfeddd78fb60d1fc44abd2bfb4e873ad72f9c61f55fef232f72797df1c5f3ebd79f6ee41e787263ffe7ebe1e3f7cfc8f562ba9dd46bbbff9617f853b87d747fff0dbc9ceaf0eaff77e1bfdff10f4ff10eba712f7f98c2e5ffefee3cddbe7fdab4afdd9fedbe3dbe397877cf6e8869ff8d9f847e21ec9df1a886a5d5fc5fef5cb71d85f5f2136e693dd2bbfb2fdd5f9ee34c68b1b3fd95df81f3822dd529012c5e0aca3c7d0d0a2b9984775579a1422968af4a16c75b6a853868d146bb29bafd57bf591ee5658d8f65da5a4ca89289152664d9ead4b9a46412baf411cde1cd84eab4d871b4b445ab4f1dca87bf215736a3581065c8626ebab8d284ba6f6a999e758e28bda6c9d92d5e125d01945cc9acc28a5ae9e4c596b923653ae1d8eeae6a82dd5952d7af1cedc666dad7131e3661597793bca79a9e9f43a44a75a0d1ba1bd2a4bde1c25b6d573567332acd61ca9ccd6c21165519f2bbada82bbdc58bb08e7a80dcf2bf952f1cdcf6aca5b6c14daa298c81ab5484e80158588205735d42331c1daa0b67a19492b95be9891fdd509c3c2daa6a1d8a8388d99b291b551eb684cade49274722e2d5834da6ac498155a3d46711bde2bfca328387726c1e429255611fc39c956827fa4b2694e18353574a020b38eaeb820032c9eb5b3a27638ba0c8fbbf55f79ca1f798abf785254afddb2b05a88337473f02cc9a5a18659a8f7c095a366a9018ed14b4124699074e5b06a63cdde4afd4814714f7dc03a26a9566822596088ba29f6955238a7ea35a210e709e05087e53cb850302af891f1c2211de4f74c0821fa44525521e733d660499a2660c5f39417c4cc1b52d639418f96ac5b47c8de6c59f24acc52aba43459cbe8a02b2fa0a223902b422d80baa152ad0ded09e1810699eb53a6943bb04470d1051dd63296d4ce9d4d6b080a99a4644e188d1ba7300f5fbde429bda319f3a6918016720aeaeb421e6666e1155e5a05a0033fa55aee358fac782dc580aee4895c46c9191db169486938242a6b6bab4ee0271d6fac49c5b8d2445c15c9c4ff81a324302872998e0e402f8c8a847fc2542ae83244f371d8a40c8a32b0406c6b3a55b7d085990bea403141a1016bab3813bea4af341600fed7fee5b1f91a038e7c6b63ae730c1a54f2c044f1d19cc27006e64c91858fcff7236d687b97b15a6f35013a4f9b0fef68e195e17f95ac984cfd6e1fe6f67c71bd9e5f8c9b8b6d0cdf0d4fe0c056c27bcfeaea34ebed6cb5843a8202c3f0a932bd28b263d2d1d4d35ade6df37c7f7e81b74621f0cd1ffe04fcd737d04f080000","ca81eebe6173470f1de992d03ec508831fb18f61741902af38ba68c5ff2e8c98b60efc0a1a1a174ac8681d0a145296f74658aa7580c6c6bc94d231cba203231370ad0347635271e13e1fa34a19533d69d05def3674cbacb65c372bc97c35af2d211acc4ad5f607306a573a7b49ae7d6b36eab93ca95566a49c26f561b956eda5799a8c66271849d8304c3f86d1a5c5febfb9113433637c3410249587e60691dc49e49080bb117ccf95863e169c6522c20e43b783c845c0c020d62b1cd4198c548f90229745842fc1e836c7fd34d9a941e5b1a2e46eb18ef96d9ac4f0385d97568fe5eb5eef7957f1db6e745bab540ea5dd6cdbffb61d37f3a69db2e6ec6e559fddbb6d9efaf40423adc499d8ff4956847f6245972df71c4392bf8fa1a717d186588e8e515762ab05a45d29148623955c04c31d555c496a0872562049b543af1842ec0f8662f04807c28d501180e35138c1503010a91503a8744026586abc01c362e48898951e3294351c823e3bcb10d645c28ae8e5b8a735219f3bede18f0d7be5da7e3c1d6c862c5f4c784c461b7cb79b8def1296dff4b6ed16bf7e56266f289353e5f9375ce9dd89a660b359cfef4bbc1fb1ba1f6d5c65361698c1437c52b2d05aa36332fd1c36e9597b9b4f87244fd29693cdb0bd0b497bfed8e72dbd9f2662bd29756f86fe84ee9f04ff8b57f51a6e8dc9fbe0669146ecad608663267c448ed8688817d8c274e709c6d86b167c90ca092a1c974c6378025ec24d857c8e6b607fcc0bc48313484786ccf11f0b05a98c6bb05d2ddd1167182c60ce50f0f39e6304f1df69cca2b7f4a7702380fb923efb9173797b7abca19b5abddfa5a277e8de34e6ccd27abf31ac56fb83ebe63ecdf3eda93f424ca5e89f4b6be4bc455eb6e0b310bdb3cb621c893afe45a090331e080a8e78e51872de69ab88e416a9a03ce790d11d78928a31e2a7a37e01d17397853c068321963079462610f8ab877de430450285d2100e64226a348b0089935887c024a6c7706ca97beadf672052450610891710c10e48f9b916493e6291f3c9244d3acb75a79c947a9d45354fbc6bcc77f5b5cefc7dda5c0e4fc6484829b079f493f821e72de8827a5e79d8065a5532bbe9b5bea9c3a862b269dd37d24df3710d5c8dafe9f40461fa97f8b1f7e107add11a8a0d65cc19f033c7b4571a68210e51c15934ce181b20e7bbe8558846702208fa9387f1e75981dac021e2f9a0c0111d8cef5140f3c5282012e19d1a2bb8c25c05860d487a6db48f029a33779246f67efc28e64cbfed61ab764c5a713315a65ddf55a89e75ef7832da2f1ffdf5a1b31accc3e99f4a8ad29ffad7473a3d39f6977f2ae0fda1fe8a9e4b567a72fb21e9cf74b7563e6caaa95e09b9da841b9dc755b26f87bd20a27c021fa47ecd18d7973f005ffefe1380cf3f85f376ab5a6d35b3dbd2808d5a215bf553711836e6ade5bcd4ae6575f1b6c4ae520bd36ea058d1fa38bb49134ef975af761b9687b83c7437bd7312ff8ee710aa5867263de24b8e053dad080388d932335f61c214df7f05a50201f94b190000"], { 'access-control-allow-headers': 'content-type, authorization',
        'content-encoding': 'gzip',
        'content-type': 'application/json; charset=utf-8',
        vary: 'Accept-Encoding',
        'transfer-encoding': 'chunked'});

      nock('https://test.bitgo.com:443')
      .get('/api/v1/wallet/2N9VaC4SDRNNnEy6G8zLF8gnHgkY6LV9PsX/tx/notfound')
      .reply(404, {"error":"transaction not found on this wallet"});
    });

    it('tx does not exist', function() {
      return callRPC('gettransaction', 'notfound')
      .then(expectError, function(err) {
        err.code.should.equal(-5);
        err.message.should.match(/transaction id/);
      });
    });

    it('single output', function() {
      return callRPC('gettransaction', 'a4dfeae89864f26a7e61c843aadf48c6d64b0758c16d0ba7b8823026ddbf0883')
      .then(function(result) {
        result.should.eql(results.tx1);
      });
    });

    it('multiple outputs', function() {
      return callRPC('gettransaction', 'c1cdd3653d6e7e2ce43e88d3a44f95d550f1fa800c25139d60125c668e563dfe')
      .then(function(result) {
        result.should.eql(results.tx2);
      });
    });
  });

  describe('Received by address', function() {

    before(function() {
      nock.cleanAll();

      nock('https://test.bitgo.com:443')
        .persist()
        .get('/api/v1/address/2MwGWTGZn5EHDsZoYGB2bDCdCb4wLVsDZ8E/tx?limit=500&skip=0')
        .reply(200, ["1f8b0800000000000203cd9a5b535acb1685ff8bcfc9a9eed977dfb8538094c845e4d479e82b021b502e82ecdafffdcc957db205a39110734cca2aa3c264add55f8f394677ff79b65ad8d9d2fad5683e5b9e9dfffbcfb351383b3f338a7b1db9e59c87e824d14095d33230a7238d3e39e1450acc26e59d153208464324f84d70e38976679fce825d45ac04848acf847e06d301762ef00bfe450819e02b52c41750fc817c3a9baf5777ebd5df57f0803f9c9de32fadf7f3f56c9555b9d854ae3b95c14c94aac5e5607e53c9832b1642c1f14da3b72c0e74090b3ed83fd65f4b66fffefaf4b5183d28d62cdceceae51d5fb71e1abd5c5d986de16266179d62d796ecaeccdafca998a65a31bc0725f45ffff9741667abc528fe7d9def50f1d3619592190fcba2336fc94d8eaa5e473ff6ee6af70f61b6bee8d51f1eebeea9ca674d0d968117ca9cf6acf0e6fc7c96468ba9fd1f0c8c2af1e9ec2ecec268363c3b4ff68f65fc74e6fe98fbc9ad5ddee2477d7d73089c09bc1221bd25d64ba2b8540a5c8c21396712118247a559445ea20ed62904c629c0ebb88da3e12d5e360302946577f2054069154be095e54a05270380d03e452181d368b8274607690996e7c41362ad6722061a42b29a5b882f0348ce59f6f5f100fec040ef8ff3770054f38bf19d2cd05069f072f54e54967013f976d258d15cb7dadaeef6d1018225d94f12f8ff00d090e3008cc6791ba530284b2608e39877d406cd923556811112a5ca2a229277cc52c6134fc61872082035fa1f007d640298175ea6e0a54a4930cea894064966ca59a5bd0744d81a1a791484c5085126a69921860afb0280ac43d83993e742fc6a00c55bfc89879dd9ec369dc5709bba7ddd9074b8d9dadb59b5b9e999d6b8b4dc1b66468111fd067f176b3f6815166dde16cbe2763a6e85cbbe5f554b977125c368289757fbfca1b230625ee2efc40b3b9d3ff13a7e9c12751c7ec9818c5a4511854e16f0524c002915b64e2d234ff877943b9e7cd00aff1084e5c45199f6f1a306347dd23f4623b2259d4fd4d0a01c22071e04be2f31a99845edb31a1212640d13de08013e7a820d3a38cbe8b7f851d9017a4ef43988df40ff66a9659b9556cbdd4c75974de38ab5abe5446bbb96cf0f9b507e2ac6719eeaaf23f49afa9d54ef197a053f2d5ef2b9d999d9d5ecf6520d5aa1e12f5dabd06b3d14457e31d82358984c3dbe2df25ecac795d4c7a147517c34ea540022a44c4226e354908e3b6194318e7a15b33b0eda06cf08ea2103e0841ea0a725907fd0b3dc19e50349c65b2fa2f22605c3a2499c2a1909939e81f19e2490c24949624075b589a48cca64d5b7e811dda1ea9cf373c24e406fba2955e2b81df13259f576555cdca0cdcc752a1771be4bf35d7bddf9f699be02de74da6c94cb8dfaea22dfe7c3465cdd75177237a84d1bf369be595955e5f74ac13313c9e8b23248c3915aabba7657f3ab3abfebce27a5bacf6fc61d3f7faa055f69f98e80fe00399ff7f5fde7efeee71ff53b3c966713401290c74d00e3aca43a22f9e811d124c6448521120da28f562b0ed184c4544c5c0b070cb815d4a5a80f26806212fe99000abd02f2ce4460c911546f8651081c211cbf71ed2111ad92a7e837b4893226fc4532e8457d223125787102108393fab4d63fbd5f076e6e26c54ee35eef8625bb1a57436db1ae5f2ff161dde6d8f8e8090017db581b35447ed2053d28ae1762262a0f8dfc6cd60339673761d1d86bb047507b4ab943e44ebcb953a7cef75417a139d26f12419955d408a70860caf19a0b08a08845eac059821d393a128c0534a4d8c4412994e870081decf94d93345581a3f0472b45908a62f4c15e6e3c934e6bcff1d506dd04e628cc4332524d39ea2f210a9d8412f435e800a1e31f0c5d33b79c73a72ab5d58dce77f4b4d39ccc58915f5f754abad72dd6d4f50f417752b9df193a7a64cad601b32f158a02ea12238244ccbedc69f04e2b48d132835708cc46169cb62258502e99e7d0a927e89448a00d630630940b8e2615838ea28a332719c10f8916733d2732f1e89dd58c015a5b41d12f5026d9cbd0e92fd0d18f864e2b364bebc5706e247fe0b5c15d7f5b9283d2b855ee36f9ddceb6f66a1d43dd49f53e143bf83e76fc48adf38804763c455208de623315126d01f6532594b29a33a359242e588c1fa85f3404cc3c019e63c7f7b235d52128a60cb040946359844a0ed33e28143dc95cc29c2df02536442f217a2dbc324944466c14af6087e1469d53f3abc30d9ae7b7c833b27a7b575e987bb56c894daedd9d0d0a97174c3cfa9b9b61acdd57f7f50908636f2e2f9e58f19935532b283930939b5d7b3a2a70588e58bb5b0c9d346f37afec7adcde63c75089657e767567ef61bd8020e54722a88332ce60fc50847aecb454486505a3560247de34e7a88104fd5af4109028e259d67cd33304f913824a719f1cfa3b8b97e898c3468b5d9c1b2730b7bb2ca6237802120629240eb9240a390c31117cb921fa650449e6f1a8fee5088a3711fc81a1de1fe9ef38bd5d87f9b9e43dba69d7ee2f37e3fea8bf9d76379d7e6ed8b74c9726fbf0708a25d94f32f84e088aef2378e412b74f8160264e94194c185a9bcc9b316515b786d248a3c852b40e38f5500695665a084982788ee0d312b7c03862f0ddcc702753a00c854fb1646422215b40c2608d626a4310012d82b53c613041cfc788e61837ec6b08662a283f7c89e7e2b1cccbeb75b92297d7f9d5f8b2948f1722fa5ca9df1f2c57ae301fee0d34793b689c52ee197ae54a3e592f7bb94dbf979faceb8f66d0646ad1aa5d751e7ab0be59ef3b36437fbaffd2ef8377e4da226608f472946290409fafa30d924a3479980302709c22c6534a032aa14d92a03704c73984f81cbca7b5c5e48ca60e030a4dc4a82c0c27405ca9c0f4e2c062d8c0f01b0903c3b053874895c649a4d06c4a9f22951f0a1e8737b756965d515edc7b43af8af33bcfe57653f051c962f531372adaca5e2dfdb6eb3ba5dc3364d6f99b5103ba8deb07a0b9f6a63e6cdcc7c7f18d432bc86bca6c0a076df7a7b1fbe709fd5ed4c9189841a8a4a75627efa38e089fc5a04b944af8566da531516a500c824f3a58cc1c88a3e42a292d0ea8e39f297c6634cb1a549c33f9e11b2ab9759ef756ac3beaf075aff9d8b9dc5e69d1cda5a26185f9a47857df9327ce304abcb5a1d214b1663bf345d3d59b83d2ed2cd6ae0737bae5fa9b72b7bd1e4f86f3837ecbb175bcb8a172e285fd920d151cd823bb2de1110547136f1d1abe284ca282a125f3841a24063b6ea23ea42443a049a13b049234c061e690443e755b15039509610a1820b446e5436b4a2d379653e6b3056f2e2d3e46703e93464ccf5907cea288d052f2f82d7e001d6ab2556dfe1b6c28b37abb7e797b3fadb6abc198a1ba8ffd95db8e1e1b2637be8e95e1c5fe3063b6e2ea2dbfb7eca782dff62a9bb6cdc1b49ccf170a6397dbe63af3c26ab5b9badf3f8b6044b6c3ff1239a75ed8afe9ba9a92231307a86c9b4e5a1339498c5bef50f20ce6cf28824e08a14b0e126298304018eb138659eee5a1fe09d04f89c3499054787485d27330e81593220e9f59488646896f56102592886d59b044903a94410aa8b2a02cc86f01a45f16f8187e7dfc8ede8fe0b24fcbfb00f83a7f27dfe4c122f743ba2d8e1e276cbe7c7cbc9ab0dc76d371bd457577bf19ebdb7a7d7c3015285e8af97a73cf01444d3a724b5904cfa4e03244a71547290c168cb52e8b0da8493a86102d844c07a9373e28ce8c4907271ab0dbeba76d0d60d2d218d1bb28028ea1a7f341673a8a2d9c48640a91c62ca3acd4c62500aa49e422dac8581068fe9e0348330001232f3b672745dea6e9d9026f17af9acd59e95156f4ae51d6c3597538b9918d9eb95cf67f684b793eaa75aaa3517eb1b90b57abe1bc9fdfde8c73d3bbe160472785ee760f972356fb4ebdb69fbda45fb4dc47d1201c297dd2a1c451c9356a9c75e8f7a90a880bda39996d94d16430e8a22a6921b95446701ea850f2606f831844e449fa30c37a40e974a86858ce272fd1d261230ec898c1542dc01a4f4cb291e8c812ce648e9aa7f1c32315e9fdc92bdb7871db4da5ce321f4ae3de43bf9f2e1fc6a237e597d58aed74f6f7397164e49b29e1f891fefc1e43fdda198653efebb7a24567675dacd2ce38a53d660863d0dc4619ac88d265076020309f7937e323219832f03b53cee1a7c5685ea4059d1a39f1fcc18fad36bdd92877b3fb51aaeeb42d8d6479121b6e359c0ef56ee174989446cbd1dd7e5bcb16bfd89b2b73a7557c86df6361b15a2eeeba93729d8dc2a8dd7b4c36f8527df97859cb5db74af2a0c9712cc17f7665ee0dbd624766852fc7601cc554eab13f3299d0ac798e7c60bf233e7aec73312a001f98d0296b6dd1266d9f13289e4ec078160847d1ca1a6222c1215b685e913c115524213b43c02d155178e213643f3865d0a631e11306e31708645f0e5fc973f2cbf7278e382e7552b9e7b85c74fc54efeaa156835279e19a838bb5c90d078fd3b57c285552ff25c57b619c0590233361b2d97626d3067b49e43450104e2862854be8a0bdd4411bcc78c172c129a6419188a752b98371d6543f654212349a27743b462b9af9219c1d04a2e792a13d4a4210990db3e2980b71cef88c2cedb2035534388c862f8c3364a7dc516938fff84c58ecf3fc653116b76d51bf1a2fc70fdd66f9a1715f5a14db71d0ba15ddfd51d6ef6c8a9ef6bc5f6853275ed9af098554b063b74205aa8bf02e1a4e40338ef31d74d6e8d050a3a141c1c8764131c991209321de2624d54be70f1054666f2b147ba7d080dd0b454411e53da63eed220a98b22405243b5896d0293920c094b0d9e9128b81131c3a7350ef8fe00f4c6cf3cec7da5e0d60275ed3ef34d0805a03017b043a21e1d1ce088c6111d018696539c3e1e7e87735048acd247a150c2a4f303c3b81a18cf72f0f349c033f17fac35d4d936eee6acb876a30b76a55ba559d5da1b9b8e2f785d1202f7bb5f95d677f84e431477a4fac78bad27c7e1fa98137a4e6c81366425847984e9480492c302975b254f16c0d14fd88e1e8b3312ea1d93690edd808c4c44aa79f13f8c5392e5776f13700ffbb25804f67abf9cafe91fdf7afff02d3400a1306360000"], {
        'content-encoding': 'gzip',
        'content-type': 'application/json; charset=utf-8'
      });
    });

    it('getreceivedbyaddress no args', function() {
      return callRPC('getreceivedbyaddress')
      .then(expectError, function(err) {
        err.code.should.equal(-1);
      });
    });

    it('getreceivedbyaddress bad address', function() {
      return callRPC('getreceivedbyaddress', 'foo')
      .then(expectError, function(err) {
        err.code.should.equal(-5);
        err.message.should.match(/Invalid Bitcoin address/);
      });
    });

    it('getreceivedbyaddress', function() {
      return callRPC('getreceivedbyaddress', '2MwGWTGZn5EHDsZoYGB2bDCdCb4wLVsDZ8E')
      .then(function(result) {
        result.should.equal(62.4198);
      });
    });

    it('getreceivedbyaddress minconfirms', function() {
      return callRPC('getreceivedbyaddress', '2MwGWTGZn5EHDsZoYGB2bDCdCb4wLVsDZ8E', 3200)
      .then(function(result) {
        result.should.equal(60.4198);
      });
    });

    it('getreceivedbyaddress minconfirms 2', function() {
      return callRPC('getreceivedbyaddress', '2MwGWTGZn5EHDsZoYGB2bDCdCb4wLVsDZ8E', 15391)
      .then(function(result) {
        result.should.equal(1);
      });
    });

    it('getreceivedbyaddress minconfirms yields nothing', function() {
      return callRPC('getreceivedbyaddress', '2MwGWTGZn5EHDsZoYGB2bDCdCb4wLVsDZ8E', 16000)
      .then(function(result) {
        // TODO: fix JSON-RPC lib returning null here
        assert(!result);
      });
    });

  });

  describe('Send to address', function(done) {

    before(function() {
      nock.cleanAll();

      nock('https://test.bitgo.com:443')
        .persist()
        .get('/api/v1/wallet/2N9VaC4SDRNNnEy6G8zLF8gnHgkY6LV9PsX')
        .reply(200, {"id":"2N9VaC4SDRNNnEy6G8zLF8gnHgkY6LV9PsX","label":"Test Wallet 1","isActive":true,"type":"safehd","freeze":{"time":"2015-01-19T19:42:04.212Z","expires":"2015-01-19T19:42:14.212Z"},"adminCount":1,"private":{"keychains":[{"xpub":"xpub661MyMwAqRbcEfREDmUVK3o5wekgo2kMd8P7tZK8zrDgB454cuVJsUN5XzzwmdFRwjooWmmj6oovEZLoa66iHMBqv9JurunU6qKuCvcpMDh","path":"/0/0"},{"xpub":"xpub661MyMwAqRbcFSu5cKZMN8LdcTZ14ADiopVd6SpgCLhpENP2VXLZLcarfN1qwJYx8yuyp6QkmFWaYLk4LLDR5DMTWEMKb69UzhKXcxPP2XG","path":"/0/0"},{"xpub":"xpub661MyMwAqRbcGeVsWGCm1sagwUJS7AKJjW1GztdKx4wp1UP9xpNs5PKPqVF6xaX9jQX3Z2i6dT5oJycFEdthymPViwRAmrFggvASmbjWaeu","path":"/0/0"}]},"permissions":"admin,spend,view","admin":{},"spendingAccount":true,"confirmedBalance":81873005758,"balance":81873005758,"pendingApprovals":[]});
    });

    it('sendtoaddress bad address', function() {
      return callRPC('sendtoaddress', '2N3So1bs9fuLeA3MrsBGPmkaYMXGWQn1HWA', 1.00, 'bad address')
      .then(expectError, function(err) {
        err.code.should.equal(-5);
        err.message.should.match(/Invalid Bitcoin address/);
      });
    });

    it('sendtoaddress bad amount', function() {
      return callRPC('sendtoaddress', '2N3So1bs9fuLeA3MrsBGPmkaYMXGWQn1HWG', -1, 'bad amount')
      .then(expectError, function(err) {
        err.code.should.equal(-3);
        err.message.should.match(/Invalid amount/);
      });
    });

    it('sendtoaddress success', function() {
      nock('https://test.bitgo.com:443')
        .get('/api/v1/wallet/2N9VaC4SDRNNnEy6G8zLF8gnHgkY6LV9PsX/unspents?target=211010000')
        .reply(200, {"unspents":[{"confirmations":228,"address":"2N2XYoQKXQGUXJUG7AvjA1LAGWzf65RcBHG","tx_hash":"ed426d37e56919485bec45c61043596781c09af0e9637998fcace7f59631c5ae","tx_output_n":0,"value":10000000000,"script":"a91465cf7dc1dc237ad59225140773994a747674e42387","redeemScript":"5221021971b4d7c5d919e2655134ac12daa755cd1d6a14996c5b272de24178f3649e952103f8bb35d209e20c1f64f9f2c5686efbcb212a504d3c5ee65e9623187c03009a9321036d051911592ef2a7a72bd53c767d1e57f260c7627a8115d6204d9f33c7dbcc7b53ae","chainPath":"/0/27"}],"pendingTransactions":false});

      nock('https://test.bitgo.com:443')
        .post('/api/v1/wallet/2N9VaC4SDRNNnEy6G8zLF8gnHgkY6LV9PsX/address/1', {"chain":1})
        .reply(200, {"address":"2NAeb4PGKKBEFdUt2seThoomcR4YR5SpbuK","chain":1,"index":80,"path":"/1/80","redeemScript":"52210306d7f5f0c559ff585f215c54d769f3fa9460193e334d16c162b97d1d06c812f82103798fb98f249f00e93523cb6d60102ac9aed44288b1482b9d35b6d70d315ae4c621025d3bc26ba30510772f4404d00c5d907dbd17f7838a4facbf157e817fc6694f5053ae"});

      nock('https://test.bitgo.com:443')
        .post('/api/v1/tx/send')
        .reply(200, {"transaction":"aaa","transactionHash":"65ab38cd15e980ac2e4337f08b84fb53fcd71e1f5d1bb114554ef43ee67617a6"});

      return callRPC('sendtoaddress', '2N3So1bs9fuLeA3MrsBGPmkaYMXGWQn1HWG', 1.11, 'this one goes to eleven')
      .then(function(result) {
        result.should.equal('65ab38cd15e980ac2e4337f08b84fb53fcd71e1f5d1bb114554ef43ee67617a6');
      });
    });
  });

  describe('Send many', function(done) {

    var recipients = {
      '2N4LzyvT64t9HXHaNXLVMugN4zyAfo9QQya': 1,
      '2N4kx6jh2zTtS681zaKA9t2Po91k2F84yfA': 2
    };

    var badAddrRecipients = {
      '2N4LzyvT64t9HXHaNXLVMugN4zyAfo9QQyA': 1,
      '2N4kx6jh2zTtS681zaKA9t2Po91k2F84yfA': 2
    };

    var badAmountRecipients = {
      '2N4LzyvT64t9HXHaNXLVMugN4zyAfo9QQya': -1,
      '2N4kx6jh2zTtS681zaKA9t2Po91k2F84yfA': 2
    };

    before(function() {
      nock.cleanAll();
      nock('https://test.bitgo.com:443')
        .persist()
        .get('/api/v1/wallet/2N9VaC4SDRNNnEy6G8zLF8gnHgkY6LV9PsX')
        .reply(200, {"id":"2N9VaC4SDRNNnEy6G8zLF8gnHgkY6LV9PsX","label":"Test Wallet 1","isActive":true,"type":"safehd","freeze":{"time":"2015-01-19T19:42:04.212Z","expires":"2015-01-19T19:42:14.212Z"},"adminCount":1,"private":{"keychains":[{"xpub":"xpub661MyMwAqRbcEfREDmUVK3o5wekgo2kMd8P7tZK8zrDgB454cuVJsUN5XzzwmdFRwjooWmmj6oovEZLoa66iHMBqv9JurunU6qKuCvcpMDh","path":"/0/0"},{"xpub":"xpub661MyMwAqRbcFSu5cKZMN8LdcTZ14ADiopVd6SpgCLhpENP2VXLZLcarfN1qwJYx8yuyp6QkmFWaYLk4LLDR5DMTWEMKb69UzhKXcxPP2XG","path":"/0/0"},{"xpub":"xpub661MyMwAqRbcGeVsWGCm1sagwUJS7AKJjW1GztdKx4wp1UP9xpNs5PKPqVF6xaX9jQX3Z2i6dT5oJycFEdthymPViwRAmrFggvASmbjWaeu","path":"/0/0"}]},"permissions":"admin,spend,view","admin":{},"spendingAccount":true,"confirmedBalance":81873005758,"balance":81650985758,"pendingApprovals":[],"unconfirmedSends":null,"unconfirmedReceives":null});
    });

    it('sendmany no recipients', function() {
      return callRPC('sendmany', "", {})
      .then(expectError, function(err) {
        err.code.should.equal(-6);
        err.message.should.match(/Transaction amounts must be positive/);
      });
    });

    it('sendmany bad address', function() {
      return callRPC('sendmany', "", badAddrRecipients)
      .then(expectError, function(err) {
        err.code.should.equal(-5);
        err.message.should.match(/Invalid Bitcoin address/);
      });
    });

    it('sendmany no recipients', function() {
      return callRPC('sendmany', "", badAmountRecipients)
      .then(expectError, function(err) {
        err.code.should.equal(-3);
        err.message.should.match(/Invalid amount/);
      });
    });

    it('sendmany insufficient funds', function() {
      nock('https://test.bitgo.com:443')
        .get('/api/v1/wallet/2N9VaC4SDRNNnEy6G8zLF8gnHgkY6LV9PsX/unspents?target=400010000')
        .reply(200, {"unspents":[{"confirmations":1,"address":"2Mven9jcBoUHa1VQRZ9Jy8nffSqw8wKZQME","tx_hash":"65ab38cd15e980ac2e4337f08b84fb53fcd71e1f5d1bb114554ef43ee67617a6","tx_output_n":1,"value":9888990000,"script":"a914255ccaf2136ed07f8bf6377710c45bfc1e83ecdb87","redeemScript":"5221023386c28561433f727a66ecd952021717a657aa2676c3e9d0960b2cdebe9020822103aa1b8b73bcd211b8d007495da84deed00e41e27445af4beb5e0187a5b4665f71210251e6b6148fba4449d2c5825b338349afed6c7e05054caafc799888de879412ea53ae","chainPath":"/1/79"}],"pendingTransactions":false});

      return callRPC('sendmany', "", recipients, 3)
      .then(expectError, function(err) {
        err.code.should.equal(-6);
        err.message.should.match(/Insufficient funds/);
      });
    });

    it('sendmany success', function() {
      nock('https://test.bitgo.com:443')
        .get('/api/v1/wallet/2N9VaC4SDRNNnEy6G8zLF8gnHgkY6LV9PsX/unspents?target=400010000')
        .reply(200, {"unspents":[{"confirmations":1,"address":"2Mven9jcBoUHa1VQRZ9Jy8nffSqw8wKZQME","tx_hash":"65ab38cd15e980ac2e4337f08b84fb53fcd71e1f5d1bb114554ef43ee67617a6","tx_output_n":1,"value":9888990000,"script":"a914255ccaf2136ed07f8bf6377710c45bfc1e83ecdb87","redeemScript":"5221023386c28561433f727a66ecd952021717a657aa2676c3e9d0960b2cdebe9020822103aa1b8b73bcd211b8d007495da84deed00e41e27445af4beb5e0187a5b4665f71210251e6b6148fba4449d2c5825b338349afed6c7e05054caafc799888de879412ea53ae","chainPath":"/1/79"}],"pendingTransactions":false});

      nock('https://test.bitgo.com:443')
        .post('/api/v1/wallet/2N9VaC4SDRNNnEy6G8zLF8gnHgkY6LV9PsX/address/1', {"chain":1})
        .reply(200, {"address":"2N5p9bXC4poJEb5jNcbu2BxuNeSn2qbEtpo","chain":1,"index":82,"path":"/1/82","redeemScript":"52210389f7e8e63adfcaa99b11523cbbd9df20ba6ff1a1ff8a2a68e27cb3e8bf21c5172103025ca7a7efedf5d3b544d7f87ee86cb0e1287dea9b5f2d98696d6c555a2dc8a021032d488227abffbd9a10a771bdc8ac469cc6f136a054b83dc826a3e252656cbc0653ae"});

      nock('https://test.bitgo.com:443')
        .post('/api/v1/tx/send')
        .reply(200, {"transaction":"0000","transactionHash":"31b74078116169c64a304bbf593cbe68027ab12a8b274c53a5c367cda3f8898f"});

      return callRPC('sendmany', "", recipients)
      .then(function(result) {
        result.should.equal('31b74078116169c64a304bbf593cbe68027ab12a8b274c53a5c367cda3f8898f');
      });
    });
  });

  describe('Set tx fee', function() {

    before(function() {
      nock.cleanAll();

      nock('https://test.bitgo.com:443')
      .persist()
      .get('/api/v1/wallet/2N9VaC4SDRNNnEy6G8zLF8gnHgkY6LV9PsX')
      .reply(200, {"id":"2N9VaC4SDRNNnEy6G8zLF8gnHgkY6LV9PsX","label":"Test Wallet 1","isActive":true,"type":"safehd","freeze":{"time":"2015-01-19T19:42:04.212Z","expires":"2015-01-19T19:42:14.212Z"},"adminCount":1,"private":{"keychains":[{"xpub":"xpub661MyMwAqRbcEfREDmUVK3o5wekgo2kMd8P7tZK8zrDgB454cuVJsUN5XzzwmdFRwjooWmmj6oovEZLoa66iHMBqv9JurunU6qKuCvcpMDh","path":"/0/0"},{"xpub":"xpub661MyMwAqRbcFSu5cKZMN8LdcTZ14ADiopVd6SpgCLhpENP2VXLZLcarfN1qwJYx8yuyp6QkmFWaYLk4LLDR5DMTWEMKb69UzhKXcxPP2XG","path":"/0/0"},{"xpub":"xpub661MyMwAqRbcGeVsWGCm1sagwUJS7AKJjW1GztdKx4wp1UP9xpNs5PKPqVF6xaX9jQX3Z2i6dT5oJycFEdthymPViwRAmrFggvASmbjWaeu","path":"/0/0"}]},"permissions":"admin,spend,view","admin":{},"spendingAccount":true,"confirmedBalance":81873005758,"balance":81873005758,"pendingApprovals":[]});
    });

    it('getinfo', function() {
      return callRPC('settxfee', 138)
      .then(function(result) {
        result.should.equal(true);
        return callRPC('getinfo')
      })
      .then(function(result) {
        result.bitgod.should.equal(true);
        result.version.should.equal(pjson.version);
        result.testnet.should.equal(true);
        result.token.should.equal(true);
        result.paytxfee.should.equal(138);
      });
    });

    it('send should fail with insufficient funds', function() {

      nock('https://test.bitgo.com:443')
      .get('/api/v1/wallet/2N9VaC4SDRNNnEy6G8zLF8gnHgkY6LV9PsX/unspents?target=211010000')
      .reply(200, {"unspents":[{"confirmations":228,"address":"2N2XYoQKXQGUXJUG7AvjA1LAGWzf65RcBHG","tx_hash":"ed426d37e56919485bec45c61043596781c09af0e9637998fcace7f59631c5ae","tx_output_n":0,"value":10000000000,"script":"a91465cf7dc1dc237ad59225140773994a747674e42387","redeemScript":"5221021971b4d7c5d919e2655134ac12daa755cd1d6a14996c5b272de24178f3649e952103f8bb35d209e20c1f64f9f2c5686efbcb212a504d3c5ee65e9623187c03009a9321036d051911592ef2a7a72bd53c767d1e57f260c7627a8115d6204d9f33c7dbcc7b53ae","chainPath":"/0/27"}],"pendingTransactions":false});

      nock('https://test.bitgo.com:443')
      .post('/api/v1/wallet/2N9VaC4SDRNNnEy6G8zLF8gnHgkY6LV9PsX/address/1', {"chain":1})
      .reply(200, {"address":"2NAeb4PGKKBEFdUt2seThoomcR4YR5SpbuK","chain":1,"index":80,"path":"/1/80","redeemScript":"52210306d7f5f0c559ff585f215c54d769f3fa9460193e334d16c162b97d1d06c812f82103798fb98f249f00e93523cb6d60102ac9aed44288b1482b9d35b6d70d315ae4c621025d3bc26ba30510772f4404d00c5d907dbd17f7838a4facbf157e817fc6694f5053ae"});

      nock('https://test.bitgo.com:443')
      .post('/api/v1/tx/send')
      .reply(200, {"transaction":"aaa","transactionHash":"65ab38cd15e980ac2e4337f08b84fb53fcd71e1f5d1bb114554ef43ee67617a6"});

      return callRPC('sendtoaddress', '2N3So1bs9fuLeA3MrsBGPmkaYMXGWQn1HWG', 1.11, 'this one goes to eleven')
      .then(expectError, function(err) {
        err.message.should.match(/fee rate too generous/);

        return callRPC('settxfee', 0.001);
      });
    })
  });

  describe('Freeze wallet', function(done) {

    before(function() {
      nock.cleanAll();
    });

    it('freezewallet invalid duration', function() {
      nock('https://test.bitgo.com:443')
        .post('/api/v1/wallet/2N9VaC4SDRNNnEy6G8zLF8gnHgkY6LV9PsX/freeze', {"duration":-10})
        .reply(400, {"error":"invalid duration"});

      return callRPC('freezewallet', -10)
      .then(expectError, function(err) {
        err.message.should.match(/invalid duration/);
      });
    });

    it('freezewallet', function() {
      nock('https://test.bitgo.com:443')
        .post('/api/v1/wallet/2N9VaC4SDRNNnEy6G8zLF8gnHgkY6LV9PsX/freeze', {"duration":10})
        .reply(200, {"time":"2015-01-30T20:16:20.233Z","expires":"2015-01-30T20:16:30.233Z"});

      return callRPC('freezewallet', 10)
      .then(function(result) {
        result.time.should.equal('2015-01-30T20:16:20.233Z');
        result.expires.should.equal('2015-01-30T20:16:30.233Z');
      });
    });

    it('send fails after freezewallet', function() {

      nock('https://test.bitgo.com:443')
        .get('/api/v1/wallet/2N9VaC4SDRNNnEy6G8zLF8gnHgkY6LV9PsX')
        .reply(200, {"id":"2N9VaC4SDRNNnEy6G8zLF8gnHgkY6LV9PsX","label":"Test Wallet 1","isActive":true,"type":"safehd","freeze":{"time":"2015-01-30T20:22:15.961Z","expires":"2015-01-30T20:22:25.961Z"},"adminCount":1,"private":{"keychains":[{"xpub":"xpub661MyMwAqRbcEfREDmUVK3o5wekgo2kMd8P7tZK8zrDgB454cuVJsUN5XzzwmdFRwjooWmmj6oovEZLoa66iHMBqv9JurunU6qKuCvcpMDh","path":"/0/0"},{"xpub":"xpub661MyMwAqRbcFSu5cKZMN8LdcTZ14ADiopVd6SpgCLhpENP2VXLZLcarfN1qwJYx8yuyp6QkmFWaYLk4LLDR5DMTWEMKb69UzhKXcxPP2XG","path":"/0/0"},{"xpub":"xpub661MyMwAqRbcGeVsWGCm1sagwUJS7AKJjW1GztdKx4wp1UP9xpNs5PKPqVF6xaX9jQX3Z2i6dT5oJycFEdthymPViwRAmrFggvASmbjWaeu","path":"/0/0"}]},"permissions":"admin,spend,view","admin":{},"spendingAccount":true,"confirmedBalance":81350975758,"balance":80708955758,"pendingApprovals":[],"unconfirmedReceives":null,"unconfirmedSends":null});


      nock('https://test.bitgo.com:443')
        .get('/api/v1/wallet/2N9VaC4SDRNNnEy6G8zLF8gnHgkY6LV9PsX/unspents?target=200010000')
        .reply(200, {"unspents":[{"confirmations":0,"address":"2NEgkNLZcU9c9usDFTZ5c4YffCWA7gR3GMQ","tx_hash":"83b4d9cc64eb494659daa4fe244f3152d05100629793a4ff5fbb71a5bce110a4","tx_output_n":1,"value":71440985758,"script":"a914eb2e66914b73199857f669ba96d2f105d59f4b2387","redeemScript":"5221030f9653fee93fc9cd9f01d0e5af17d0c5dcc02babae2abc605eb64fc69ecdb2482102a2cf52c0addb5ae6587ddf275c6b32dac6265f66616a0fb00ff23ea4b11b681a21032b6f31e70d87fdba586e149bc6d78dde8814e529259a4a85314335d54c8dd5e453ae","chainPath":"/1/84"}],"pendingTransactions":false});

      nock('https://test.bitgo.com:443')
        .post('/api/v1/wallet/2N9VaC4SDRNNnEy6G8zLF8gnHgkY6LV9PsX/address/1', {"chain":1})
        .reply(200, {"address":"2N4Jxq3Z4GJoPucrgghFm75R8bLv8q1GTD3","chain":1,"index":86,"path":"/1/86","redeemScript":"5221025f9015b8ab25457a36cda1cfeef40af9210ebfc0ac9ee014e38a72100df1f4dc210367718564ea653156e5711ccb6d438d4e571dc35fb25990cb88bc894af96682122102c796b0baf1b5d11c3a2cbeed01158dd3aec81ea33c213555c94c24ce39fcf14453ae"});

      nock('https://test.bitgo.com:443')
        .post('/api/v1/tx/send')
        .reply(403, {"error":"wallet is frozen, cannot spend"});

      return callRPC('sendmany', "", {'2N3So1bs9fuLeA3MrsBGPmkaYMXGWQn1HWG': 1}, 0, 'frozen')
      .then(expectError, function(err) {
        err.message.should.match(/wallet is frozen, cannot spend/);
      });
    });

  });


  describe('Lock wallet', function(done) {

    before(function() {
      nock.cleanAll();
    });

    it('walletlock', function() {
      return callRPC('walletlock')
      .then(function(result) {
        assert(result === null);
      });
    });

    it('cannot send after walletlock', function() {
      nock('https://test.bitgo.com:443')
        .get('/api/v1/wallet/2N9VaC4SDRNNnEy6G8zLF8gnHgkY6LV9PsX')
        .reply(200, {"id":"2N9VaC4SDRNNnEy6G8zLF8gnHgkY6LV9PsX","label":"Test Wallet 1","isActive":true,"type":"safehd","freeze":{"time":"2015-01-19T19:42:04.212Z","expires":"2015-01-19T19:42:14.212Z"},"adminCount":1,"private":{"keychains":[{"xpub":"xpub661MyMwAqRbcEfREDmUVK3o5wekgo2kMd8P7tZK8zrDgB454cuVJsUN5XzzwmdFRwjooWmmj6oovEZLoa66iHMBqv9JurunU6qKuCvcpMDh","path":"/0/0"},{"xpub":"xpub661MyMwAqRbcFSu5cKZMN8LdcTZ14ADiopVd6SpgCLhpENP2VXLZLcarfN1qwJYx8yuyp6QkmFWaYLk4LLDR5DMTWEMKb69UzhKXcxPP2XG","path":"/0/0"},{"xpub":"xpub661MyMwAqRbcGeVsWGCm1sagwUJS7AKJjW1GztdKx4wp1UP9xpNs5PKPqVF6xaX9jQX3Z2i6dT5oJycFEdthymPViwRAmrFggvASmbjWaeu","path":"/0/0"}]},"permissions":"admin,spend,view","admin":{},"spendingAccount":true,"confirmedBalance":81650985758,"balance":81350975758,"pendingApprovals":[],"unconfirmedReceives":null,"unconfirmedSends":null});

      nock('https://test.bitgo.com:443')
      .get('/api/v1/wallet/2N9VaC4SDRNNnEy6G8zLF8gnHgkY6LV9PsX/unspents?target=414010000')
      .reply(200, {"unspents":[{"confirmations":1,"address":"2Mven9jcBoUHa1VQRZ9Jy8nffSqw8wKZQME","tx_hash":"65ab38cd15e980ac2e4337f08b84fb53fcd71e1f5d1bb114554ef43ee67617a6","tx_output_n":1,"value":9888990000,"script":"a914255ccaf2136ed07f8bf6377710c45bfc1e83ecdb87","redeemScript":"5221023386c28561433f727a66ecd952021717a657aa2676c3e9d0960b2cdebe9020822103aa1b8b73bcd211b8d007495da84deed00e41e27445af4beb5e0187a5b4665f71210251e6b6148fba4449d2c5825b338349afed6c7e05054caafc799888de879412ea53ae","chainPath":"/1/79"}],"pendingTransactions":false});

      nock('https://test.bitgo.com:443')
      .post('/api/v1/wallet/2N9VaC4SDRNNnEy6G8zLF8gnHgkY6LV9PsX/address/1', {"chain":1})
      .reply(200, {"address":"2N4Jxq3Z4GJoPucrgghFm75R8bLv8q1GTD3","chain":1,"index":86,"path":"/1/86","redeemScript":"5221025f9015b8ab25457a36cda1cfeef40af9210ebfc0ac9ee014e38a72100df1f4dc210367718564ea653156e5711ccb6d438d4e571dc35fb25990cb88bc894af96682122102c796b0baf1b5d11c3a2cbeed01158dd3aec81ea33c213555c94c24ce39fcf14453ae"});

      return callRPC('sendtoaddress', '2N3So1bs9fuLeA3MrsBGPmkaYMXGWQn1HWG', 3.14, 'have some pi')
      .then(expectError, function(err) {
        err.code.should.equal(-13);
        err.message.should.match(/Please use walletpassphrase or setkeychain first/);
      });
    });

    it('lock', function() {
      nock('https://test.bitgo.com:443')
        .post('/api/v1/user/lock')
        .reply(200, {"session":{"client":"bitgo","user":"5461addd9b904dac1200003353061409","scope":["user_manage","openid","profile","wallet_create","wallet_manage_all","wallet_approve_all","wallet_spend_all","wallet_edit_all","wallet_view_all"],"expires":"2015-01-30T20:39:06.859Z","origin":"test.bitgo.com"}});
      return callRPC('lock')
      .then(function(result) {
        result.should.equal('Locked');
      });
    });

  });
});
