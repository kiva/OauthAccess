# OauthAccess


```
// Create an OauthAccess instance
var oauth = new OauthAccess({
    callback: ''
    , key: ''
    , accessTokens: {
        token: ''
        , tokenSecret: ''
        , scope: ''
    }
});

// Attach an "Authorization" header to your request
$.ajax({
	url: 'someurl.com'
	, beforeSend: function(jqXhr, options) {
		jqXhr.setRequestHeader('Authorization', oauth.generateHeader(options.type, options.url););
	}
});
```