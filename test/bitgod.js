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

var BitGoD = require('../src/bitgod');

describe('BitGoD', function() {

  var bitgod;
  var client;
  var callRPC;

  var expectError = function() { assert(false); };

  before(function() {
    nock.disableNetConnect();
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
        .reply(200, ["1f8b0800000000000203dd98596f22d71685ff0bcfeeab330fbc19cc20c0081bb029aeeec319999aa18b020aa2feefd9b893183b746c13478a2e2f0854b5d8e79cafd65e9b5f0a596a166be3b2c972b12e14fffb4b61e20bc582553444ec8c121a2311a2541e09cd11b1c630e22c368451cb4c54d632ee1c532e50af981218512670e1aae04d16408920ccbf20fc05d31e4145448b58fd072134842b62800b287c405785e5265b6db21f156ce143a1085f1ae7969b45765469eb075366dd9bfb767b51d98b9a3ab4aa6ab4a88f6689683de8ce7a00825bf375039212fdf6ba2a4cd6b793057c95a59bf0fdea7769fc52fabadcde4e197dd8b61fc5ed61d4ebde307e379f4db266c767b69ad867698624d14ffadfff7755088b2c9d841f459f0a964b594ed7e315eeec69ba1cb0d01b0cb01fca60cd12afead38767c12f4c4afaa3da637d7f77c5af352e5e9a5b2ee2249d9bdfb82048c1a6adc2c24f16a342319aafeb7055b05f976e3636eb31fcd6ef156846bde5dc20ee30c25a33c271704e38e6b015d1481dbdf198186fbd95da2987b1f0c44021e330198da16e8a15d6eab894271683d64e46a588d20a516a1095945a1c8857d6694f344134288210c32e60a395b41613a784024c31a7675944b8485591f3172ce277b2f881f365e4f468cee2c7423e3e8cca6e9194dbf90197bbf3eb9d14adada8d7e74bb5ed3f3eab29ca08c5844bae5eb1fd3934beacf64218bf3ca9e09f910487f03e9202c29e082dec919bc0b1024f42d1a3e00201c7e1510613831247e3a19a4beca4b2d2d9972421f94c12010d11b84304312d39362e18ed9920946b2f14589d0d5153e5b5e1809b725a608f95857b903721fe9924a47b08c1b61589bc8824824b191f4eef463c3c365ab5cd6894909b38abeff371a769cca8f4bcadfc2d906ef778902efda4d1a0a1de9c95abc9e1c176746950f71dda6bec68e30424c51125fa63205d5aeca51cf1bfc24809fa4e43524652693422de45460d958a68c5823360761853112358079cbe96d4020aea789da5e405469261f10746d2e300c2c2196102dcefa54288ba209da19c316489134631e379a482111fac6612690bd872aaa2f97c8c7027bbede0eab6d3c8076ad2df647696df3fdc9795c85d1eaa62fc118cb6f7ae339f0da703522a3725f1bd","ca81eebe6173470f1de992d03ec508831fb18f61741902af38ba68c5ff2e8c98b60efc0a1a1a174ac8681d0a145296f74658aa7580c6c6bc94d231cba203231370ad0347635271e13e1fa34a19533d69d05def3674cbacb65c372bc97c35af2d211acc4ad5f607306a573a7b49ae7d6b36eab93ca95566a49c26f561b956eda5799a8c66271849d8304c3f86d1a5c5febfb9113433637c3410249587e60691dc49e49080bb117ccf95863e169c6522c20e43b783c845c0c020d62b1cd4198c548f90229745842fc1e836c7fd34d9a941e5b1a2e46eb18ef96d9ac4f0385d97568fe5eb5eef7957f1db6e745bab540ea5dd6cdbffb61d37f3a69db2e6ec6e559fddbb6d9efaf40423adc499d8ff4956847f6245972df71c4392bf8fa1a717d186588e8e515762ab05a45d29148623955c04c31d555c496a0872562049b543af1842ec0f8662f04807c28d501180e35138c1503010a91503a8744026586abc01c362e48898951e3294351c823e3bcb10d645c28ae8e5b8a735219f3bede18f0d7be5da7e3c1d6c862c5f4c784c461b7cb79b8def1296dff4b6ed16bf7e56266f289353e5f9375ce9dd89a660b359cfef4bbc1fb1ba1f6d5c65361698c1437c52b2d05aa36332fd1c36e9597b9b4f87244fd29693cdb0bd0b497bfed8e72dbd9f2662bd29756f86fe84ee9f04ff8b57f51a6e8dc9fbe0669146ecad608663267c448ed8688817d8c274e709c6d86b167c90ca092a1c974c6378025ec24d857c8e6b607fcc0bc48313484786ccf11f0b05a98c6bb05d2ddd1167182c60ce50f0f39e6304f1df69cca2b7f4a7702380fb923efb9173797b7abca19b5abddfa5a277e8de34e6ccd27abf31ac56fb83ebe63ecdf3eda93f424ca5e89f4b6be4bc455eb6e0b310bdb3cb621c893afe45a090331e080a8e78e51872de69ab88e416a9a03ce790d11d78928a31e2a7a37e01d17397853c068321963079462610f8ab877de430450285d2100e64226a348b0089935887c024a6c7706ca97beadf672052450610891710c10e48f9b916493e6291f3c9244d3acb75a79c947a9d45354fbc6bcc77f5b5cefc7dda5c0e4fc6484829b079f493f821e72de8827a5e79d8065a5532bbe9b5bea9c3a862b269dd37d24df3710d5c8dafe9f40461fa97f8b1f7e107add11a8a0d65cc19f033c7b4571a68210e51c15934ce181b20e7bbe8558846702208fa9387f1e75981dac021e2f9a0c0111d8cef5140f3c5282012e19d1a2bb8c25c05860d487a6db48f029a33779246f67efc28e64cbfed61ab764c5a713315a65ddf55a89e75ef7832da2f1ffdf5a1b31accc3e99f4a8ad29ffad7473a3d39f6977f2ae0fda1fe8a9e4b567a72fb21e9cf74b7563e6caaa95e09b9da841b9dc755b26f87bd20a27c021fa47ecd18d7973f005ffefe1380cf3f85f376ab5a6d35b3dbd2808d5a215bf553711836e6ade5bcd4ae6575f1b6c4ae520bd36ea058d1fa38bb49134ef975af761b9687b83c7437bd7312ff8ee710aa5867263de24b8e053dad080388d932335f61c214df7f05a50201f94b190000"], { 'access-control-allow-headers': 'content-type, authorization',
        'content-encoding': 'gzip',
        'content-type': 'application/json; charset=utf-8',
        vary: 'Accept-Encoding',
        'transfer-encoding': 'chunked'});

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