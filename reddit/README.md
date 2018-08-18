## Reddit Getter

#### This is a simple script with the purpose of requesting json objects from the Reddit social network.

Various configurations strings are obtained from **config.ini** such as:

* redirect_uri
* state
* scope
* user agent

Tokens will also be stored in there. Expiration timestamp is generated to assist automatic refresh.

Expiration datetime is also generated for informative purposes.

Various other boolean settings:

* Pretty print
* Print to console
* Save to a file
* Debugging for print the strings of various operations

Its only dependency is the "requests" library.

It is intended to work as standalone calling it from cli. Quickstart:

`reddit_getter.py` with no arguments will either:

* Attempt new authorization if no tokens are stored, _or..._
* Refresh stored tokens

else:

**reddit_getter.py** [_command_] [_url_] [_post_data_]

where:

**command** can be: refresh, revoke, get, post

`refresh` will refresh access token

`revoke` will reset all tokens and timestamps

`get` and `post` commands require a url which can either full or path only, the script will automatically join the path.

`post` requires _post_data_ in this form "{'key1': 'value1', 'key2': 'value2'}"
