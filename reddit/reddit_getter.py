#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function

from distutils.dist import strtobool
import requests.auth
import sys, time, webbrowser, json
from ConfigParser import SafeConfigParser
from ast import literal_eval
from datetime import datetime
from urllib import urlencode

config = SafeConfigParser()
config.read('config.ini')

redirect_uri = config.get('strings', 'redirect_uri')
state = config.get('strings', 'state')
scope = config.get('strings', 'scope')
user_agent = config.get('strings', 'user_agent')

client_id = config.get('tokens', 'client_id')
auth_token = config.get('tokens', 'auth_token')
access_token = config.get('tokens', 'access_token')
refresh_token = config.get('tokens', 'refresh_token')

try:
    expiration_stamp = float(config.get('tokens', 'expiration_stamp'))
except ValueError:
    expiration_stamp = 0

try:
    pretty_print = strtobool(config.get('misc', 'json_pretty_print'))
except ValueError:
    print('Invalid pretty print setting')
    pretty_print = False

try:
    save_to_file = strtobool(config.get('misc', 'save_to_file'))
except ValueError:
    print('Invalid "save to file" setting')
    save_to_file = False

try:
    print_to_console = strtobool(config.get('misc', 'print_to_console'))
except ValueError:
    print('Invalid "print to console" setting')
    print_to_console = False

try:
    debugging = strtobool(config.get('misc', 'debugging'))
except ValueError:
    print('Invalid debugging setting')
    debugging = False


def base_link(override=False):

    base = 'www' if override else 'oauth'

    return 'https://{0}.reddit.com'.format(base)


def authorization_link():

    return base_link(True) + '/api/v1/authorize?client_id={0}&response_type=code&state={1}&redirect_uri={2}&duration=permanent&scope={3}'.format(client_id, state, redirect_uri, scope)


def api_link(end_point):

    return '{0}/api/v1/{1}'.format(base_link(True), end_point)


def request_headers():

    headers = {'User-Agent': user_agent, 'Authorization': 'bearer ' + access_token}

    return headers


def timestamp_to_datetime(timestamp):

    timestamp = float(timestamp)

    string = datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d,%H:%M:%S')

    return string


def get_tokens(code=None, refresh=False):

    if not code:
        code = auth_token

    if refresh:
        post_data = {'grant_type': 'refresh_token', 'refresh_token': refresh_token}
        if debugging:
            print('Attempting to refresh tokens...')
    else:
        post_data = {'grant_type': 'authorization_code', 'code': code, 'redirect_uri': redirect_uri}
        if debugging:
            print('Getting new tokens...')

    headers = {'User-Agent': user_agent}
    client_auth = requests.auth.HTTPBasicAuth(client_id, '')
    response = requests.post(api_link('access_token'), auth=client_auth, data=post_data, headers=headers)

    tokens = response.json()

    if debugging:
        if pretty_print:
            print(json.dumps(tokens, indent=4, sort_keys=True))
        else:
            print(tokens)

    if 'error' in tokens:
        try:
            if debugging:
                print('Authorization failed, reason: ' + tokens.get('error'))
        except TypeError:
            if debugging:
                print('Failure in general!')
        tokens_reset()
        return

    config.set('tokens', 'access_token', tokens['access_token'])
    timestamp = str(float(time.time() + float(tokens['expires_in'])))
    converted = timestamp_to_datetime(timestamp)
    if debugging:
        print('Access token will expire on: ' + converted)
    config.set('tokens', 'expiration_stamp', timestamp)
    config.set('tokens', 'expiration_time', converted)

    if not refresh:
        config.set('tokens', 'refresh_token', tokens['refresh_token'])
        config.set('tokens', 'auth_token', code)

    with open('config.ini', 'w') as configfile:
        config.write(configfile)

    if debugging:
        print('Success!')


def tokens_reset():

    config.set('tokens', 'auth_token', '')
    config.set('tokens', 'access_token', '')
    config.set('tokens', 'refresh_token', '')
    config.set('tokens', 'expiration_stamp', '')
    config.set('tokens', 'expiration_time', '')

    with open('config.ini', 'w') as configfile:
        config.write(configfile)


def revoke():

    post_data = {'token': access_token}
    headers = {'User-Agent': user_agent}
    client_auth = requests.auth.HTTPBasicAuth(client_id, '')
    response = requests.post(api_link('revoke_token'), auth=client_auth, data=post_data, headers=headers)

    print(response)

    tokens_reset()

    print('Tokens have been reset')


def token_refresh():

    if expiration_stamp < time.time():

        get_tokens(refresh=True)


if __name__ == '__main__':

    try:
        boolean = not access_token or sys.argv[1].startswith('auth')
    except IndexError:
        boolean = not access_token

    if boolean:

        if not auth_token:

            if debugging:

                print('App has not been authorized, opening authorization link')

            time.sleep(1)

            webbrowser.open(authorization_link())

            auth_token = raw_input('Please enter reddit\'s authorization token: ')

        if not auth_token:

            if debugging:

                 print('This script will not work without an authorization token')

            sys.exit(1)

        else:

            get_tokens(code=auth_token, refresh=False)

    else:

        if len(sys.argv) == 1:

            if debugging:

                print('This script won\'t work without additional arguments, it will just refresh the access token')

            get_tokens(refresh=True)

        elif len(sys.argv) == 2:

            command = sys.argv[1]

            if command != 'refresh':

                token_refresh()

            if command == 'revoke':

                revoke()

            elif command == 'refresh':

                get_tokens(refresh=True)

            else:

                print('Did not understood arguments, try again')

        elif len(sys.argv) in [3, 4]:

            token_refresh()

            command = sys.argv[1]
            url = sys.argv[2]

            if not url.startswith('http'):
                url = base_link(override=False) + url

                if debugging:

                    print('Joined url: ' + url)

            if command == 'get':

                response = requests.get(url, headers=request_headers())

                if print_to_console:

                    if pretty_print:
                        print(json.dumps(response.json(), indent=4, sort_keys=True))
                    else:
                        print(response.json())

                else:

                    if debugging:

                        print('Print to console is disabled')

                if save_to_file:

                    with open('output.json', 'w') as f:
                        if pretty_print:
                            f.write(json.dumps(response.json(), indent=4, sort_keys=True))
                        else:
                            f.write(json.dumps(response.json()))

            elif command == 'post':

                try:
                    post = sys.argv[3]
                    post = literal_eval(post)
                    # if isinstance(post, )
                except IndexError:
                    post = None

                response = requests.get(url, headers=request_headers(), data=urlencode(post))

                if print_to_console:

                    if pretty_print:

                        print(json.dumps(response.json(), indent=4, sort_keys=True))

                    else:

                        print(response.json())

                else:

                    if debugging:

                        print('Print to console is disabled')

                if save_to_file:

                    with open('output.json', 'w') as f:
                        if pretty_print:
                            f.write(json.dumps(response.json(), indent=4, sort_keys=True))
                        else:
                            f.write(json.dumps(response.json()))

            else:

                if debugging:
                    print('Did not understood arguments, try again')

        else:

            if debugging:

                print('Too many arguments passed, make sure to place post arguments inside quotes, quiting....')

            sys.exit(1)
