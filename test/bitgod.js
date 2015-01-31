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