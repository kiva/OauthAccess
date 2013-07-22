'use strict';

var undefined;

/**
 *
 * @param settings
 * @constructor
 */
function OauthAccess(settings) {
	OauthAccess.extend(this, settings);
}


OauthAccess.extend = function (target, obj) {
	for(var key in obj) {
		if (obj.hasOwnProperty(key)) {
			target[key] = obj[key];
		}
	}
};


/**
 * Converts a data object into an array
 *
 * @param obj
 * @returns {Array}
 */
OauthAccess.arrayify = function (obj) {
	if (typeof obj != 'object') {
		throw 'Data must be an [object]'
	}

	var arr = [];
	for (var key in obj) {
		if (obj.hasOwnProperty(key)) {
			arr.push({
				key: key
				, val: obj[key]
			});
		}
	}

	return arr;
};


OauthAccess.generateNonce = function () {
	return Math.random() * 10000000;
};


OauthAccess.generateTimestamp = function () {
	return parseInt((new Date()).getTime()/1000, 10);
};


OauthAccess.serializeParams = function (params) {
	var str = '', i;

	for (i = 0; i < params.length; i++) {
		str += params[i].key + '%3D' + params[i].val;
		if (i < params.length - 1) {
			str += '%26';
		}
	}

	return str;
};


OauthAccess.parseQueryParams = function (queryStr) {
	var split
		, queryParamsArray = []
		, pairs = queryStr.split('&');

	for (var i = 0; i < pairs.length; i++) {
		split = pairs[i].split('=');
		queryParamsArray.push({key: split[0], val: split[1]});
	}

	return queryParamsArray;
};


OauthAccess.encodeParams = function (params) {
	var i, newParams = [];

	for (i = 0; i < params.length; i++) {
		newParams[i] = {
			key: encodeURIComponent(params[i].key)
			, val: encodeURIComponent(params[i].val)
		};
	}

	return newParams;
};


OauthAccess.sortParams = function (params) {
	return params.sort(function (a, b) {
		var aKey = a.key, bKey = b.key;

		if (aKey < bKey) {
			return -1;
		}

		if (aKey > bKey) {
			return 1;
		}

		return 0;
	});
};


/**
 *
 * @param {String} httpMethod
 * @param {String} baseUrl
 * @param {String} params
 * @param {String} nonce
 * @param {String} timestamp
 * @param {String} token
 * @param {String} tokenSecret
 * @param {String} key
 * @param {String} callback
 * @return {String}
 */
OauthAccess.generateSignature = function (httpMethod, baseUrl, params, nonce, timestamp, token, tokenSecret, key, callback) {
	var base;

	params = params || [];

	params.push({key: 'oauth_callback', val: callback});
	params.push({key: 'oauth_consumer_key', val: key});
	params.push({key: 'oauth_nonce', val: nonce});
	params.push({key: 'oauth_signature_method', val: 'HMAC-SHA1-QI'});
	params.push({key: 'oauth_timestamp', val: timestamp});
	params.push({key: 'oauth_token', val: token});
	params.push({key: 'oauth_version', val: '1.0'});

	params = OauthAccess.sortParams(params);
	params = OauthAccess.encodeParams(params);
	params = OauthAccess.serializeParams(params);

	base = httpMethod.toUpperCase() + '&' + encodeURIComponent(baseUrl).toString() + '&' + params;
	return b64_hmac_sha1(tokenSecret, base) + '=';
};


OauthAccess.prototype = {

	_generateHeader: function (httpMethod, url, params, token, tokenSecret, key, callback) {
		params = params
			? OauthAccess.arrayify(params)
			: [];

		if (typeof httpMethod != 'string') {
			httpMethod = 'GET';
		}

		if (! url) {
			throw 'Unable to generate an authorization header: No "url" provided';
		}

		callback = encodeURIComponent(callback);
		key = encodeURIComponent(key);
		token = encodeURIComponent(token);

		var baseUrl, signature
		, nonce = OauthAccess.generateNonce()
		, timestamp = OauthAccess.generateTimestamp()
		, queryStart = url.indexOf('?');

		if (queryStart > -1) {
			baseUrl = url.slice(0, queryStart);
			params.concat(OauthAccess.parseQueryParams(url.slice(queryStart + 1)));
		} else {
			baseUrl = url;
		}

		signature = OauthAccess.generateSignature(httpMethod, baseUrl, params, nonce, timestamp, token, encodeURIComponent(tokenSecret), key, encodeURIComponent(callback));

		return 'OAuth oauth_nonce="' + encodeURIComponent(nonce) +
			'",oauth_callback="' + callback +
			'",oauth_signature_method="HMAC-SHA1-QI"' +
			',oauth_timestamp="' + encodeURIComponent(timestamp) +
			'",oauth_consumer_key="' + key +
			'",oauth_signature="' + signature +
			'",oauth_token="' + token +
			'",oauth_version="1.0"';
	}


	, generateHeader: function (httpMethod, baseUrl, params) {
		var accessTokens = this.accessTokens;
		return this._generateHeader(httpMethod, baseUrl, params, accessTokens.token, accessTokens.tokenSecret, this.key, this.callback);
	}
};