## Features

* No assumptions about tokens storage type.
* You can store arbitrary data assosiated with issued token.
* Secret for authenticity verification. This may be a secret based on IP address and port.

## Install

`npm install oauth2-token-manager`

## Usage examples

### Generate exchange code

```
tokenManager
	.generateExchangeCode('123|10.10.10.10|8888', 'www.abcd.com')
    .then(function(obj){
    	assert.ok(obj.accessToken);
    	assert.ok(obj.refreshToken);
    });
```

### Exchange code for token

```
tokenManager
	.exchange(exchangeCode, redirectUri)
	.then(function(obj){
    	assert.ok(obj.accessToken);
		assert.ok(obj.refreshToken);
    });
```

### Verify access token

```
tokenManager
	.verify(accessToken)
	.spread(function(result, userData){
    	assert.ok(result);
        // using userData
        ...
    });
```

### Generate access token

```
tokenManager
	.generateAccessToken('123|10.10.10.10|8888')
	.then(function(obj){
    	assert.ok(obj.accessToken);
		assert.ok(obj.refreshToken);
    });    	
```

### Refresh access token

```
tokenManager
	.refresh(obj.refreshToken)
    .then(function(obj){
    	assert.ok(obj.accessToken);
		assert.ok(obj.refreshToken);
    });
```

## API reference

* [generateAccessToken](#generateAccessToken)
* [generateExchangeCode](#generateExchangeCode)
* [verify](#verify)
* [exchange](#exchange)
* [refresh](#refresh)
* [serialize](#serialize)
* [deserialize](#deserialize)
* [type: TokenObject](#TokenObject)
* [type: StorageObject](#StorageObject)
* [callback: serializeCallback](#serializeCallback)
* [callback: deserializeCallback](#deserializeCallback)

<a name="generateAccessToken"></a>
### generateAccessToken(key, [userData], [secret])
Generate a token and store it associated with a key.

**Params**

- key `string` - Uniq key associated with a token in storage. This may be "[userId]|[IP]|[TCP port]" string. A key will be hashed before serialization.
- \[userData\] `object` - Data to serialize with a generated access token.  
- \[secret\] `string` - Data for source authenticity verification.  

**Returns**: `promise` - A promise to return.								[TokenObject](#TokenObject)

<a name="generateExchangeCode"></a>
### generateExchangeCode(key, redirectUri, [userData], [secret])
Generate an exchange code and store it associated with a key.

**Params**

- key `string` - Uniq key associated with a token in storage. This may be "[userId]|[IP]|[TCP port]" string. A key will be hashed before serialization.
- redirectUri `string` - Redirect URI  
- \[userData\] `object` - Data to serialize with a generated exchange code.  
- \[secret\] `string` - Data for source authenticity verification.  

**Returns**: `promise` - A promise to return an exchange code.

<a name="verify"></a>
### verify(token, [secret])
Verify a token validity.

**Params**

- token `string` - A accessToken to validate.  
- \[secret\] `string` - Data for source authenticity verification.		 This may be used to prevent of accessToken using from other IP.			An accessToken had to be generated with the same secret.  

**Returns**: `promise` - A promise to return true for a valid token, false for a not and an optional user data if deserialize callback supports it.		Be sure to use the `spread` method like this `spread(function(result, userData){})`.

<a name="exchange"></a>
### exchange(code, redirectUri, [secret])
Exchange a code for a token.

**Params**

- code `string` - A code to exchange for a token.  
- redirectUri `string` - This is the redirectUri that was passed to generateCode earlier.  
- \[secret\] `string` - Data for source authenticity verification. This has to be the same data that was passed to generateCode earlier.  

**Returns**: `promise` - A promise to return [TokenObject](#TokenObject) or null.

<a name="refresh"></a>
### refresh(refreshToken, [secret])
Refresh an accessToken.

**Params**

- refreshToken `string` - A refreshToken to exchange for a new accessToken.  
- \[secret\] `string` - Data for source authenticity verification. This had to be the same data that was passed to generateAccessToken earlier.  

**Returns**: `promise` - A promise to return [TokenObject](#TokenObject).

<a name="serialize"></a>
### serialize(cb)
Set a function to serialize a token in storage.

**Params**

- cb <code>[serializeCallback](#serializeCallback)</code> - Serialization callback.

<a name="deserialize"></a>
### deserialize(cb)
Set a function to deserialize a token from storage.

**Params**

- cb <code>[deserializeCallback](#deserializeCallback)</code> - Derialization callback.

<a name="TokenObject"></a>
### type: TokenObject
**Properties**

- accessToken `string`  
- refreshToken `string`  

**Type**: `Object`

<a name="StorageObject"></a>
### type: StorageObject
**Properties**

- code1 `string` - `code1` serializeCallback parameter  
- code2 `string` - `code2` serializeCallback parameter  
- createdAt `string` - `createdAt` serializeCallback parameter  
- expiresIn `string` - `expiresIn` serializeCallback parameter  

**Type**: `Object`

<a name="serializeCallback"></a>
## callback: serializeCallback
Serialize an access token or an exchange code object in a storage.

**Params**

- key `string` - Primary key for an object.  
- code1 `string` - An access token or null.  
- code2 `string` - A refresh token or an exchange code.  
- createdAt `string` - Time in seconds since epoch.  
- expiresIn `string` - Expiration time in seconds.  
- \[userData\] `object` - Additional user data.  

**Type**: `function`  
**Returns**: `promise` - A promise to store the object that contains code1, code2, createdAt and expiresIn parameters.                       The deffered must be resolved with `true` value on success.

<a name="deserializeCallback"></a>
## callback: deserializeCallback
Deserialize an access token or an exchange code object from a storage.

**Params**

- key `string` - `key` serializeCallback parameter.  

**Type**: `function`  
**Returns**: `promise` - A promise to return [StorageObject](#StorageObject).  
