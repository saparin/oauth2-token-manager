/**
 * OAauth2 token manager.
 * 
 * @module oauth2-token-manager
 */

var crypto = require('crypto-lite').crypto
  ,	_ = require('underscore');

module.exports = {
	/**
	 * Generate a token and store it associated with a key.
	 * 
	 * @param	{string}	key			Uniq key associated with a token in storage. This may be "[userId]|[IP]|[TCP port]" string.
	 * 									A key will be hashed before serialization;
	 * @param	{object}	[userData]	Data to serialize with a generated access token.
	 * @param	{string}	[secret]	Data for source authenticity verification.
	 * @return	{promise}				A promise to return.
	 * 									{@link module:oauth2-token-manager.TokenObject an access token object}
	 */
	generateAccessToken: function(key, userData, secret){
		if (!_.isFunction(serializeCallback)) {
			throw new Error('Serialize callback required');
		}
		var encryptedKey = encryptKey(key, secret);
		var date = new Date();
		var accessTokenObject = generateToken(encryptedKey, date, secret);
		var refreshTokenObject = generateToken(encryptedKey, date, secret);
		
		return 	serializeCallback(	encryptedKey,
							accessTokenObject.toStore,
							refreshTokenObject.toStore,
							Math.round(date.getTime()/1000),
							this.accessTokenExpTimeSec,
							userData)
				.then(function(){
					return {
						accessToken: accessTokenObject.toIssue,
						refreshToken: refreshTokenObject.toIssue
					};
				});
	},
	/**
	 * Generate an exchange code and store it associated with a key.
	 * 
	 * @param	{string}	key			Uniq key associated with a token in storage. This may be "[userId]|[IP]|[TCP port]" string.
	 * 									A key will be hashed before serialization.
	 * @param	{string}	redirectUri	Redirect URI
	 * @param	{object}	[userData]	Data to serialize with a generated exchange code.
	 * @param	{string}	[secret]	Data for source authenticity verification.
	 * @return	{promise}				A promise to return an exchange code.
	 */
	generateExchangeCode: function(key, redirectUri, userData, secret){
		if (!_.isFunction(serializeCallback)) {
			throw new Error('Serialize callback required');
		}
		var finalSecret = secret ? (secret + '|' + redirectUri) : redirectUri;
		var encryptedKey = encryptKey(key, finalSecret);
		var date = new Date();
		var exchangeCodeObject = generateToken(encryptedKey, date, finalSecret);

		return	serializeCallback(	encryptedKey,
							null,
							exchangeCodeObject.toStore,
							Math.round(date.getTime()/1000),
							this.exchangeCodeExpTimeSec,
							userData)
				.then(function(){
					return exchangeCodeObject.toIssue;
				});
	},
	/**
	 * Verify a token validity.
	 * 
	 * @param	{string}	token		A accessToken to validate.
	 * @param	{string}	[secret]	Data for source authenticity verification.
	 *		 							This may be used to prevent of accessToken using from other IP.
	 * 									An accessToken had to be generated with the same secret.
	 * @return	{promise}				A promise to return true for a valid token, false for a not and an optional user data
	 * 									if deserialize callback supports it.
	 * 									Be sure to use the `spread` method like this spread(result, userData).
	 */ 
	verify: function(token, secret){
		if (!_.isFunction(deserializeCallback)) {
			throw new Error('Deserialize callback required');
		}
		var encryptedKey = token.slice(0, 8);
		
		return	deserializeCallback(encryptedKey)
				.then(function(obj){
					var tokenToVerify = secret ? crypto.hmac('sha1', secret, token) : token;
					var tokenFromStorage = obj.code1;
					var date = new Date();
					currentTimeSec = Math.round(date.getTime()/1000);
					return [((tokenToVerify == tokenFromStorage) &&
							currentTimeSec < (obj.createdAt + obj.expiresIn)),
							obj.userData];
				});
	},
	/**
	 * Exchange a code for a token.
	 * 
	 * @param	{string}	code		A code to exchange for a token.
	 * @param	{string}	redirectUri	This is the redirectUri that was passed to generateCode earlier.
	 * @param	{string}	[secret]	Data for source authenticity verification.
	 * 									This has to be the same data that was passed to generateCode earlier.
	 * @return	{promise}				A promise to return {@link module:oauth2-token-manager.TokenObject an access token object} or null.
	 */
	exchange: function(code, redirectUri, secret){
		if (!_.isFunction(deserializeCallback)) {
			throw new Error('Deserialize callback required');
		}
		var encryptedKey = code.slice(0, 8);
		var self = this;

		return 	deserializeCallback(encryptedKey)
				.then(function(obj){
					// Check if wrong key part in code was passed
					if (!obj) return [null];

					// Check if wrong code was passed
					var finalSecret = secret ? (secret + '|' + redirectUri) : redirectUri;
					var codeToVerify = crypto.hmac('sha1', finalSecret, code);
					var codeFromStorage = obj.code2;
					if (codeToVerify != codeFromStorage) return [null];
					// Check if code passed is stale
					var date = new Date();
					currentTimeSec = Math.round(date.getTime()/1000);
					if (currentTimeSec >= (obj.createdAt + obj.expiresIn)) return [null];
					
					// All checks are successfull. Let us serialize new token object.
					var accessTokenObject = generateToken(encryptedKey, date, secret);
					var refreshTokenObject = generateToken(encryptedKey, date, secret);
					return	[	serializeCallback(	encryptedKey,
												accessTokenObject.toStore,
												refreshTokenObject.toStore,
												currentTimeSec,
												self.accessTokenExpTimeSec,
												obj.userData),
								accessTokenObject,
								refreshTokenObject];
				})
				.spread(function(result, accessTokenObject, refreshTokenObject){
					if (result) {
						return {
							accessToken: accessTokenObject.toIssue,
							refreshToken: refreshTokenObject.toIssue
						};
					} else {
						return null;
					}
				});
	},
	/**
	 * Refresh an accessToken.
	 * 
	 * @param	{string}	refreshToken	A refreshToken to exchange for a new accessToken.
	 * @param	{string}	[secret]			Data for source authenticity verification.
	 * 										This had to be the same data that was passed to generateAccessToken earlier.
	 * @return	{promise}					A promise to return {@link module:oauth2-token-manager.TokenObject a new access token object}.
	 */
	refresh: function(refreshToken, secret){
		if (!_.isFunction(deserializeCallback)) {
			throw new Error('Deserialize callback required');
		}
		var encryptedKey = refreshToken.slice(0, 8);
		var self = this;

		return 	deserializeCallback(encryptedKey)
				.then(function(obj){
					// Check if wrong key part in refreshToken was passed
					if (!obj) return [null];

					// Check if wrong refreshToken was passed
					var refreshTokenToVerify = secret ? crypto.hmac('sha1', secret, refreshToken) : refreshToken;
					var refreshTokenFromStorage = obj.code2;
					if (refreshTokenToVerify != refreshTokenFromStorage) return [null];
					
					// All checks are successfull. Let us serialize new token object.
					var date = new Date();
					var accessTokenObject = generateToken(encryptedKey, date, secret);
					var refreshTokenObject = generateToken(encryptedKey, date, secret);
					return	[	serializeCallback(	encryptedKey,
												accessTokenObject.toStore,
												refreshTokenObject.toStore,
												currentTimeSec,
												self.accessTokenExpTimeSec),
								accessTokenObject,
								refreshTokenObject];
				})
				.spread(function(result, accessTokenObject, refreshTokenObject){
					if (result) {
						return {
							accessToken: accessTokenObject.toIssue,
							refreshToken: refreshTokenObject.toIssue
						};
					} else {
						return null;
					}
				});
	},
	/**
	 * Set a function to serialize a token in storage.
	 * 
	 * @param	{module:oauth2-token-manager.serializeCallback}		cb	Serialization callback.
	 */
	serialize: function(cb){
		serializeCallback = cb;
	},
	/**
	 * Set a function to deserialize a token from storage.
	 * 
	 * @param	{module:oauth2-token-manager.deserializeCallback}	cb	Deserialization callback.
	 */
	deserialize: function(cb){
		deserializeCallback = cb;
	},
	accessTokenExpTimeSec: 43200,
	exchangeCodeExpTimeSec: 3600
}

/**
 * Serialize an access token or an exchange code object in a storage.
 * 
 * @callback	serializeCallback
 * @memberOf	module:oauth2-token-manager
 * @param	{string}	key			Primary key for an object.
 * @param	{string}	code1		An access token or null.
 * @param	{string}	code2		A refresh token or an exchange code.
 * @param	{string}	createdAt	Time in seconds since epoch.
 * @param	{string}	expiresIn	Expiration time in seconds.
 * @param	{object}	[userData]	Additional user data.
 * @return	{promise}				A promise to store the object that contains code1, code2, createdAt and expiresIn parameters.
 * 									but just might return a value if it doesn’t need to defer
 * 									The deffered must be resolved with `true` value on success.
 */
var serializeCallback = null;

/**
 * Deserialize an access token or an exchange code object from a storage.
 * 
 * @callback	deserializeCallback
 * @memberOf	module:oauth2-token-manager
 * @param	{string}	key		`key` serializeCallback parameter.
 * @return	{promise} 			A promise to return {@link module:oauth2-token-manager.StorageObject a storage object}.
 */
var deserializeCallback = null;

/*
 * Helper functions
 */
function generateToken(encryptedKey, date, secret){
	var salt = Math.random().toString();
	var code = crypto.sha1(salt);
	var toIssue = encryptedKey + code.slice(8);
	var toStore = secret ? crypto.hmac('sha1', secret, toIssue) : toIssue;
	return {toIssue: toIssue, toStore: toStore};
}

function encryptKey(key, secret){
	return crypto.hmac('sha1', (secret || 'secret'), key).slice(0, 8);
}

/**
 * @typedef		{Object}	module:oauth2-token-manager.TokenObject
 * @property	{string}	accessToken
 * @property	{string}	refreshToken
 */

/**
 * @typedef		{Object}	module:oauth2-token-manager.StorageObject
 * @property	{string}	code1		`code1` serializeCallback parameter
 * @property	{string}	code2		`code2` serializeCallback parameter
 * @property	{string}	createdAt	`createdAt` serializeCallback parameter
 * @property	{string}	expiresIn	`expiresIn` serializeCallback parameter
 */
