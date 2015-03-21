var assert = require('assert')
  ,	Q = require('q')
  ,	_ = require('underscore')
  ,	crypto = require('crypto-lite').crypto
  ,	tokenManager = require('./lib/index');

/*
 * Callbacks
 */
 
tokenManager.serialize(function(key, code1, code2, createdAt, expiresIn, userData){
	tokenStorage[key] = {
		code1: code1,
		code2: code2,
		createdAt: createdAt,
		expiresIn: expiresIn,
		userData: userData
	};
	return Q.all(true);
});

tokenManager.deserialize(function(key){
	return Q.all(tokenStorage[key]);
});

var tokenStorage = {};

it('generateAccessToken with no secret', function(cb){
	var d1 = new Date();
	tokenManager
	.generateAccessToken('123|10.10.10.10|8888')
	.then(function(obj){
		var d2 = new Date();
		assert.ok(_.isString(obj.accessToken), 'accessToken is not a string');
		assert.equal(obj.accessToken.length, 40, 'accessToken is wrong length');
		assert.ok(_.isString(obj.refreshToken), 'refreshToken is not a string');
		assert.equal(obj.refreshToken.length, 40, 'refreshToken is wrong length');
		assert.notEqual(obj.refreshToken, obj.accessToken, 'accessToken == refreshToken');
		var encryptedKeyFromAccessToken = obj.accessToken.slice(0, 8);
		var encryptedKeyFromRefreshToken = obj.refreshToken.slice(0, 8);
		assert.equal(encryptedKeyFromAccessToken, encryptedKeyFromRefreshToken, 'Tokens key parts are not the same');
		var inStorageObj = tokenStorage[encryptedKeyFromAccessToken];
		assert.ok(	(Math.round(d1.getTime()/1000) <= inStorageObj.createdAt) &&
					(Math.round(d2.getTime()/1000) >= inStorageObj.createdAt), 'createdAt is wrong');
		assert.equal(inStorageObj.expiresIn, tokenManager.accessTokenExpTimeSec, 'expiresIn is wrong');
		assert.equal(inStorageObj.code1, obj.accessToken, 'accessToken returned and accessToken in storage is not the same');
		assert.equal(inStorageObj.code2, obj.refreshToken, 'refreshToken returned and refreshToken in storage is not the same');
		cb();
	})
	.done();
});

it('generateAccessToken with a secret and an aditional user data', function(cb){
	var secret = '10.10.10.10|8888';
	tokenManager
	.generateAccessToken('123|10.10.10.10|8888', { userId: 123 }, secret)
	.then(function(obj){
		var encryptedKey = obj.accessToken.slice(0, 8);
		var inStorageObj = tokenStorage[encryptedKey];
		assert.equal(	inStorageObj.code1,
						crypto.hmac('sha1', secret, obj.accessToken),
						'accessToken returned does not correspond to accessToken in storage');
		assert.equal(	inStorageObj.code2,
						crypto.hmac('sha1', secret, obj.refreshToken),
						'refreshToken returned does not correspond to refreshToken in storage');
		assert.ok(inStorageObj.userData, 'User data was not saved in storage');
		cb();
	})
	.done();
});

it('generateExchangeCode with no secret', function(cb){
	var d1 = new Date();
	tokenManager
	.generateExchangeCode('123|10.10.10.10|8888', 'www.abcd.com')
	.then(function(exchangeCode){
		var d2 = new Date();
		assert.ok(_.isString(exchangeCode), 'exchangeCode is not a string');
		assert.equal(exchangeCode.length, 40, 'exchangeCode is wrong length');
		var encryptedKey = exchangeCode.slice(0, 8);
		var inStorageObj = tokenStorage[encryptedKey];
		assert.ok(	(Math.round(d1.getTime()/1000) <= inStorageObj.createdAt) &&
					(Math.round(d2.getTime()/1000) >= inStorageObj.createdAt), 'createdAt is wrong');
		assert.equal(inStorageObj.expiresIn, tokenManager.exchangeCodeExpTimeSec, 'expiresIn is wrong');
		assert.equal(	inStorageObj.code2,
						crypto.hmac('sha1', 'www.abcd.com', exchangeCode),
						'exchangeCode returned does not correspond to exchangeCode in storage');
		assert.ok(_.isNull(inStorageObj.code1), 'code1 in storage is not null');
		cb();
	})
	.done();
});

it('generateExchangeCode with a secret and an additional user data', function(cb){
	var secret = '10.10.10.10|8888';
	tokenManager
	.generateExchangeCode('123|10.10.10.10|8888', 'www.abcd.com', { userId: 123 }, secret)
	.then(function(exchangeCode){
		var encryptedKey = exchangeCode.slice(0, 8);
		var inStorageObj = tokenStorage[encryptedKey];
		var finalSecret = secret + '|www.abcd.com';
		assert.equal(	inStorageObj.code2,
						crypto.hmac('sha1', finalSecret, exchangeCode),
						'exchangeCode returned does not correspond to exchangeCode in storage');
		assert.ok(inStorageObj.userData, 'User data was not saved in storage');
		cb();
	})
	.done();
});

it('verify accessToken with no secret', function(cb){
	tokenManager
	.generateAccessToken('123|10.10.10.10|8888')
	.then(function(obj){
		return [obj, tokenManager.verify(obj.accessToken)];
	})
	.spread(function(obj, result){
		assert.ok(result, 'verify returned not true');
		var encryptedKey = obj.accessToken.slice(0, 8);
		var inStorageObj = tokenStorage[encryptedKey];
		inStorageObj.createdAt = 0;
		return tokenManager.verify(obj.accessToken);
	})
	.spread(function(result){
		assert.ok(!result, 'stale accessToken was not detected');
		cb();
	})
	.done();
});

it('verify accessToken with a secret and an aditional user data', function(cb){
	var secret = '10.10.10.10|8888';
	tokenManager
	.generateAccessToken('123|10.10.10.10|8888', { userId: 123 }, secret)
	.then(function(obj){
		return tokenManager.verify(obj.accessToken, secret);
	})
	.spread(function(result, userData){
		assert.ok(result, 'verify returned not true');
		assert.ok(userData, 'Additional user data was nat passed');
		cb();
	})
	.done();
});

it('exchange code for accessToken with no secret', function(cb){
	var redirectUri = 'www.abcd.com';
	var d1, d2;
	tokenManager
	.generateExchangeCode('123|10.10.10.10|8888', redirectUri)
	.then(function(exchangeCode){
		var encryptedKey = exchangeCode.slice(0, 8);
		inStorageObj = tokenStorage[encryptedKey];
		return [tokenManager.exchange(exchangeCode, 'www.dcba.com'), exchangeCode, inStorageObj];
	})
	.spread(function(obj, exchangeCode, inStorageObj){
		assert.ok(!obj, 'Test wrong redirectUri protection failed');
		d1 = new Date();

		// Make exchangeCode stale
		var createdAt = inStorageObj.createdAt;
		inStorageObj.createdAt = 0;

		return [tokenManager.exchange(exchangeCode, redirectUri), exchangeCode, createdAt];
	})
	.spread(function(obj, exchangeCode, createdAt){
		assert.ok(!obj, 'Test stale exchangeCode protection failed');

		// Restore createdAt
		inStorageObj.createdAt = createdAt;

		d1 = new Date();
		return [tokenManager.exchange(exchangeCode, redirectUri), exchangeCode];
	})
	.spread(function(obj, exchangeCode){
		d2 = new Date();
		assert.ok(obj, 'exchange returned null');

		var encryptedKey = obj.accessToken.slice(0, 8);
		var inStorageObj = tokenStorage[encryptedKey];
		
		assert.notEqual(exchangeCode, inStorageObj.code2, 'exchangeCode was not exchanged');
		assert.ok(inStorageObj.code1, 'No accessToken in storage');
		assert.ok(	(Math.round(d1.getTime()/1000) <= inStorageObj.createdAt) &&
					(Math.round(d2.getTime()/1000) >= inStorageObj.createdAt), 'createdAt is wrong');
		assert.equal(inStorageObj.expiresIn, tokenManager.accessTokenExpTimeSec, 'expiresIn is wrong');

		cb();
	})
	.done();
});

it('exchange code for accessToken with a secret and an additional user data', function(cb){
	var redirectUri = 'www.abcd.com';
	var secret = '10.10.10.10|8888';
	var d1, d2;
	tokenManager
	.generateExchangeCode('123|10.10.10.10|8888', redirectUri, { userId: 123 }, secret)
	.then(function(exchangeCode){
		return [tokenManager.exchange(exchangeCode, 'www.dcba.com', secret), exchangeCode];
	})
	.spread(function(obj, exchangeCode){
		assert.ok(!obj, 'Test wrong redirectUri protection failed');
		return [tokenManager.exchange(exchangeCode, redirectUri, 'wrong secret'), exchangeCode];
	})
	.spread(function(obj, exchangeCode){
		assert.ok(!obj, 'Test wrong secret protection failed');
		d1 = new Date();
		return [tokenManager.exchange(exchangeCode, redirectUri, secret), exchangeCode];
	})
	.spread(function(obj, exchangeCode){
		d2 = new Date();
		assert.ok(obj, 'exchange returned null');

		var encryptedKey = obj.accessToken.slice(0, 8);
		var inStorageObj = tokenStorage[encryptedKey];
		
		assert.notEqual(exchangeCode, inStorageObj.code2, 'exchangeCode was not exchanged');
		assert.ok(inStorageObj.code1, 'No accessToken in storage');
		assert.ok(	(Math.round(d1.getTime()/1000) <= inStorageObj.createdAt) &&
					(Math.round(d2.getTime()/1000) >= inStorageObj.createdAt), 'createdAt is wrong');
		assert.equal(inStorageObj.expiresIn, tokenManager.accessTokenExpTimeSec, 'expiresIn is wrong');
		assert.ok(inStorageObj.userData, 'User data was not saved in storage');

		cb();
	})
	.done();
});

it('refresh accessToken with no secret', function(cb){
	var d1, d2;
	tokenManager
	.generateAccessToken('123|10.10.10.10|8888')
	.then(function(obj){
		encryptedKey = obj.accessToken.slice(0, 8);
		inStorageObj = tokenStorage[encryptedKey];
		var createdAt = inStorageObj.createdAt;
		
		// Make accessToken stale
		inStorageObj.createdAt = 0;
		return [tokenManager.refresh(obj.refreshToken), createdAt, inStorageObj, encryptedKey];
	})
	.spread(function(obj, createdAt, inStorageObj, encryptedKey){
		assert.ok(obj, 'Refresh stale accessToken failed');
		assert.equal(obj.accessToken.slice(0, 8), encryptedKey, 'New key in storage');
		assert.notEqual(inStorageObj.accessToken, obj.accessToken, 'accessToken was not changed');
		assert.notEqual(inStorageObj.refreshToken, obj.refreshToken, 'refreshToken was not changed');

		// Restore createdAt
		inStorageObj.createdAt = createdAt;

		d1 = new Date();
		return [tokenManager.refresh(obj.refreshToken), encryptedKey];
	})
	.spread(function(obj, encryptedKey){
		d2 = new Date();
		assert.ok(obj, 'refresh returned null');
		assert.equal(obj.accessToken.slice(0, 8), encryptedKey, 'New key in storage');

		var encryptedKey = obj.accessToken.slice(0, 8);
		var inStorageObj = tokenStorage[encryptedKey];
		
		assert.ok(inStorageObj.code1, 'No accessToken in storage');
		assert.ok(	(Math.round(d1.getTime()/1000) <= inStorageObj.createdAt) &&
					(Math.round(d2.getTime()/1000) >= inStorageObj.createdAt), 'createdAt is wrong');
		assert.equal(inStorageObj.expiresIn, tokenManager.accessTokenExpTimeSec, 'expiresIn is wrong');

		cb();
	})
	.done();
});


it('refresh accessToken with a secret', function(cb){
	var d1, d2;
	var secret = '10.10.10.10|8888';
	tokenManager
	.generateAccessToken('123|10.10.10.10|8888', null, secret)
	.then(function(obj){
		return [tokenManager.refresh(obj.refreshToken, null, 'wrong secret'), obj.refreshToken];
	})
	.spread(function(obj, refreshToken){
		assert.ok(!obj, 'Refresh accessToken with wrong secret protection failed');
		return tokenManager.refresh(refreshToken, secret);
	})
	.then(function(obj){
		assert.ok(obj, 'refresh returned null');
		cb();
	})
	.done();
});
