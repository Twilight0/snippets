# -*- coding: utf-8 -*-

'''
    Tulip routine libraries, based on lambda's lamlib
    Author Twilight0

        License summary below, for more details please read license.txt file

        This program is free software: you can redistribute it and/or modify
        it under the terms of the GNU General Public License as published by
        the Free Software Foundation, either version 2 of the License, or
        (at your option) any later version.
        This program is distributed in the hope that it will be useful,
        but WITHOUT ANY WARRANTY; without even the implied warranty of
        MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
        GNU General Public License for more details.
        You should have received a copy of the GNU General Public License
        along with this program.  If not, see <http://www.gnu.org/licenses/>.
'''
from __future__ import absolute_import, division, unicode_literals, print_function

from random import choice, randrange
import re, sys, time

from compat import (
    urllib2, cookielib, urlparse, URLopener, quote_plus, unquote, unicode, unescape, range, basestring, str,
    urlsplit, urlencode, bytes, is_py3, is_py2, addinfourl
)


def request(
        url, close=True, redirect=True, error=False, proxy=None, post=None, headers=None, mobile=False, limit=None,
        referer=None, cookie=None, output='', timeout='30', username=None, password=None
):

    if isinstance(post, dict):
        if is_py2:
            post = urlencode(post)
        elif is_py3:
            post = bytes(urlencode(post), encoding='utf-8')
    elif isinstance(post, basestring) and is_py3:
        post = bytes(post, encoding='utf-8')

    try:
        handlers = []

        if username is not None and password is not None and not proxy:
            passmgr = urllib2.HTTPPasswordMgrWithDefaultRealm()
            passmgr.add_password(None, uri=url, user=username, passwd=password)
            handlers += [urllib2.HTTPBasicAuthHandler(passmgr)]
            opener = urllib2.build_opener(*handlers)
            urllib2.install_opener(opener)

        if proxy is not None:

            if username is not None and password is not None:
                passmgr = urllib2.ProxyBasicAuthHandler()
                passmgr.add_password(None, uri=url, user=username, passwd=password)
                handlers += [
                    urllib2.ProxyHandler({'http': '{0}'.format(proxy)}), urllib2.HTTPHandler,
                    urllib2.ProxyBasicAuthHandler(passmgr)
                ]
            else:
                handlers += [urllib2.ProxyHandler({'http':'{0}'.format(proxy)}), urllib2.HTTPHandler]
            opener = urllib2.build_opener(*handlers)
            urllib2.install_opener(opener)

        if output == 'cookie' or output == 'extended' or close is not True:

            cookies = cookielib.LWPCookieJar()
            handlers += [urllib2.HTTPHandler(), urllib2.HTTPSHandler(), urllib2.HTTPCookieProcessor(cookies)]

            opener = urllib2.build_opener(*handlers)
            urllib2.install_opener(opener)

        try:

            if (2, 7, 9) < sys.version_info:
                raise BaseException

            import ssl
            try:
                import _ssl
                CERT_NONE = _ssl.CERT_NONE
            except ImportError:
                CERT_NONE = ssl.CERT_NONE
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = CERT_NONE
            handlers += [urllib2.HTTPSHandler(context=ssl_context)]
            opener = urllib2.build_opener(*handlers)
            urllib2.install_opener(opener)

        except BaseException:
            pass

        try:
            headers.update(headers)
        except BaseException:
            headers = {}

        if 'User-Agent' in headers:
            pass
        elif not mobile is True:
            #headers['User-Agent'] = agent()
            headers['User-Agent'] = randomagent()
        else:
            headers['User-Agent'] = 'Apple-iPhone/701.341'

        if 'Referer' in headers:
            pass
        elif referer is None:
            headers['Referer'] = '%s://%s/' % (urlparse(url).scheme, urlparse(url).netloc)
        else:
            headers['Referer'] = referer

        if not 'Accept-Language' in headers:
            headers['Accept-Language'] = 'en-US'

        if 'Cookie' in headers:
            pass
        elif cookie is not None:
            headers['Cookie'] = cookie

        if redirect is False:

            class NoRedirectHandler(urllib2.HTTPRedirectHandler):

                def http_error_302(self, reqst, fp, code, msg, head):

                    infourl = addinfourl(fp, head, reqst.get_full_url())
                    infourl.status = code
                    infourl.code = code

                    return infourl

                http_error_300 = http_error_302
                http_error_301 = http_error_302
                http_error_303 = http_error_302
                http_error_307 = http_error_302

            opener = urllib2.build_opener(NoRedirectHandler())
            urllib2.install_opener(opener)

            try:
                del headers['Referer']
            except Exception:
                pass

        req = urllib2.Request(url, data=post, headers=headers)

        try:

            response = urllib2.urlopen(req, timeout=int(timeout))

        except urllib2.HTTPError as response:

            if response.code == 503:

                if 'cf-browser-verification' in response.read(5242880):

                    netloc = '%s://%s' % (urlparse(url).scheme, urlparse(url).netloc)

                    cf = cfcookie(netloc, headers['User-Agent'], timeout)

                    headers['Cookie'] = cf

                    req = urllib2.Request(url, data=post, headers=headers)

                    response = urllib2.urlopen(req, timeout=int(timeout))

                elif error is False:
                    return

            elif error is False:
                return

        if output == 'cookie':

            try:
                result = '; '.join(['%s=%s' % (i.name, i.value) for i in cookies])
            except BaseException:
                pass
            try:
                result = cf
            except BaseException:
                pass

        elif output == 'response':

            if limit == '0':
                result = (str(response.code), response.read(224 * 1024))
            elif limit is not None:
                result = (str(response.code), response.read(int(limit) * 1024))
            else:
                result = (str(response.code), response.read(5242880))

        elif output == 'chunk':

            try:
                content = int(response.headers['Content-Length'])
            except BaseException:
                content = (2049 * 1024)

            if content < (2048 * 1024):
                return
            result = response.read(16 * 1024)

        elif output == 'extended':

            try:
                cookie = '; '.join(['%s=%s' % (i.name, i.value) for i in cookies])
            except BaseException:
                pass
            try:
                cookie = cf
            except BaseException:
                pass
            content = response.headers
            result = response.read(5242880)
            return result, headers, content, cookie

        elif output == 'geturl':
            result = response.geturl()

        elif output == 'headers':
            content = response.headers
            return content

        else:
            if limit == '0':
                result = response.read(224 * 1024)
            elif limit is not None:
                result = response.read(int(limit) * 1024)
            else:
                result = response.read(5242880)

        if close is True:
            response.close()

        return result

    except BaseException:
        return


def retriever(source, destination, *args):

    class Opener(URLopener):
        version = randomagent()

    Opener().retrieve(source, destination, *args)


def url2name(url):

    from os.path import basename

    url = url.split('|')[0]
    return basename(unquote(urlsplit(url)[2]))


def get_extension(url, response):

    from os.path import splitext

    filename = url2name(url)
    if 'Content-Disposition' in response.info():
        cd_list = response.info()['Content-Disposition'].split('filename=')
        if len(cd_list) > 1:
            filename = cd_list[-1]
            if filename[0] == '"' or filename[0] == "'":
                filename = filename[1:-1]
    elif response.url != url:
        filename = url2name(response.url)
    ext = splitext(filename)[1][1:]
    if not ext:
        ext = 'mp4'
    return ext


def parse_headers(string):

    """
    Converts a multi-line response/request headers string into a dictionary
    :param string: string of headers
    :return: dictionary of response headers
    """

    headers = dict([line.partition(': ')[::2] for line in string.splitlines()])

    return headers


def parseDOM(html, name=u"", attrs=None, ret=False):

    """
    :param html:
        String to parse, or list of strings to parse.
    :type html:
        string or list
    :param name:
        Element to match ( for instance "span" )
    :type name:
        string
    :param attrs:
        Dictionary with attributes you want matched in the elment (for
        instance { "id": "span3", "class": "oneclass.*anotherclass",
        "attribute": "a random tag" } )
    :type attrs:
        dict
    :param ret:
        Attribute in element to return value of. If not set(or False), returns
        content of DOM element.
    :type ret:
        string
    """

    if attrs is None:
        attrs = {}

    # print("Name: " + repr(name) + " - Attrs:" + repr(attrs) + " - Ret: " + repr(ret) + " - HTML: " + str(type(html)))

    if isinstance(name, basestring): # Should be handled
        try:
            name = name.decode("utf-8")
        except BaseException:
            pass
            print("Couldn't decode name binary string: " + repr(name))

    if isinstance(html, basestring):
        try:
            html = [html.decode("utf-8")]  # Replace with chardet thingy
        except BaseException:
            html = [html]
    elif isinstance(html, unicode):
        html = [html]
    elif not isinstance(html, list):
        print("Input isn't list or string/unicode.")
        return u""

    if not name.strip():
        print("Missing tag name")
        return u""

    ret_lst = []
    for item in html:
        temp_item = re.compile('(<[^>]*?\n[^>]*?>)').findall(item)
        for match in temp_item:
            item = item.replace(match, match.replace("\n", " "))

        lst = _getDOMElements(item, name, attrs)

        if isinstance(ret, basestring):
            # print("Getting attribute %s content for %s matches " % (ret, len(lst) ))
            lst2 = []
            for match in lst:
                lst2 += _getDOMAttributes(match, name, ret)
            lst = lst2
        else:
            # print("Getting element content for %s matches " % len(lst))
            lst2 = []
            for match in lst:
                # print("Getting element content for %s" % match)
                temp = _getDOMContent(item, name, match, ret).strip()
                item = item[item.find(temp, item.find(match)) + len(temp):]
                lst2.append(temp)
            lst = lst2
        ret_lst += lst

    # print("Done: " + repr(ret_lst))
    return ret_lst


def _getDOMContent(html, name, match, ret):  # Cleanup
    # print("match: " + match)

    endstr = u"</" + name  # + ">"

    start = html.find(match)
    end = html.find(endstr, start)
    pos = html.find("<" + name, start + 1 )

    # print(str(start) + " < " + str(end) + ", pos = " + str(pos) + ", endpos: " + str(end))

    while pos < end and pos != -1:  # Ignore too early </endstr> return
        tend = html.find(endstr, end + len(endstr))
        if tend != -1:
            end = tend
        pos = html.find("<" + name, pos + 1)
        # print("loop: " + str(start) + " < " + str(end) + " pos = " + str(pos))

    # print("start: %s, len: %s, end: %s" % (start, len(match), end))
    if start == -1 and end == -1:
        result = u""
    elif start > -1 and end > -1:
        result = html[start + len(match):end]
    elif end > -1:
        result = html[:end]
    elif start > -1:
        result = html[start + len(match):]

    if ret:
        endstr = html[end:html.find(">", html.find(endstr)) + 1]
        result = match + result + endstr

    # print("done result length: " + str(len(result)))
    return result


def _getDOMAttributes(match, name, ret):

    lst = re.compile('<' + name + '.*?' + ret + '=([\'"].[^>]*?[\'"])>', re.M | re.S).findall(match)
    if len(lst) == 0:
        lst = re.compile('<' + name + '.*?' + ret + '=(.[^>]*?)>', re.M | re.S).findall(match)
    ret = []
    for tmp in lst:
        cont_char = tmp[0]
        if cont_char in "'\"":
            # print("Using %s as quotation mark" % cont_char)

            # Limit down to next variable.
            if tmp.find('=' + cont_char, tmp.find(cont_char, 1)) > -1:
                tmp = tmp[:tmp.find('=' + cont_char, tmp.find(cont_char, 1))]

            # Limit to the last quotation mark
            if tmp.rfind(cont_char, 1) > -1:
                tmp = tmp[1:tmp.rfind(cont_char)]
        else:
            # print("No quotation mark found")
            if tmp.find(" ") > 0:
                tmp = tmp[:tmp.find(" ")]
            elif tmp.find("/") > 0:
                tmp = tmp[:tmp.find("/")]
            elif tmp.find(">") > 0:
                tmp = tmp[:tmp.find(">")]

        ret.append(tmp.strip())

    # print("Done: " + repr(ret))
    return ret


def _getDOMElements(item, name, attrs):

    lst = []
    for key in attrs:
        lst2 = re.compile('(<' + name + '[^>]*?(?:' + key + '=[\'"]' + attrs[key] + '[\'"].*?>))', re.M | re.S).findall(item)
        if len(lst2) == 0 and attrs[key].find(" ") == -1:  # Try matching without quotation marks
            lst2 = re.compile('(<' + name + '[^>]*?(?:' + key + '=' + attrs[key] + '.*?>))', re.M | re.S).findall(item)

        if len(lst) == 0:
            # print("Setting main list " + repr(lst2))
            lst = lst2
            lst2 = []
        else:
            # print("Setting new list " + repr(lst2))
            test = list(range(len(lst)))
            test.reverse()
            for i in test:  # Delete anything missing from the next list.
                if not lst[i] in lst2:
                    # print("Purging mismatch " + str(len(lst)) + " - " + repr(lst[i]))
                    del(lst[i])

    if len(lst) == 0 and attrs == {}:
        # print("No list found, trying to match on name only")
        lst = re.compile('(<' + name + '>)', re.M | re.S).findall(item)
        if len(lst) == 0:
            lst = re.compile('(<' + name + ' .*?>)', re.M | re.S).findall(item)

    # print("Done: " + str(type(lst)))
    return lst


def stripTags(html):

    sub_start = html.find("<")
    sub_end = html.find(">")
    while sub_end > sub_start > -1:
        html = html.replace(html[sub_start:sub_end + 1], "").strip()
        sub_start = html.find("<")
        sub_end = html.find(">")

    return html


def replaceHTMLCodes(txt):

    txt = re.sub("(&#[0-9]+)([^;^0-9]+)", "\\1;\\2", txt)
    txt = unescape(txt)
    txt = txt.replace("&quot;", "\"")
    txt = txt.replace("&amp;", "&")
    txt = txt.replace("&#38;", "&")
    txt = txt.replace("&nbsp;", "")

    return txt


def randomagent():

    BR_VERS = [
        ['%s.0' % i for i in range(18, 50)],
        ['37.0.2062.103', '37.0.2062.120', '37.0.2062.124', '38.0.2125.101', '38.0.2125.104', '38.0.2125.111',
         '39.0.2171.71', '39.0.2171.95', '39.0.2171.99', '40.0.2214.93', '40.0.2214.111', '40.0.2214.115',
         '42.0.2311.90', '42.0.2311.135', '42.0.2311.152', '43.0.2357.81', '43.0.2357.124', '44.0.2403.155',
         '44.0.2403.157', '45.0.2454.101', '45.0.2454.85', '46.0.2490.71', '46.0.2490.80', '46.0.2490.86',
         '47.0.2526.73', '47.0.2526.80', '48.0.2564.116', '49.0.2623.112', '50.0.2661.86', '51.0.2704.103',
         '52.0.2743.116', '53.0.2785.143', '54.0.2840.71', '61.0.3163.100'],
        ['11.0'],
        ['8.0', '9.0', '10.0', '10.6']
    ]

    WIN_VERS = [
        'Windows NT 10.0', 'Windows NT 7.0', 'Windows NT 6.3', 'Windows NT 6.2', 'Windows NT 6.1', 'Windows NT 6.0',
        'Windows NT 5.1', 'Windows NT 5.0'
    ]

    FEATURES = ['; WOW64', '; Win64; IA64', '; Win64; x64', '']

    RAND_UAS = ['Mozilla/5.0 ({win_ver}{feature}; rv:{br_ver}) Gecko/20100101 Firefox/{br_ver}',
                'Mozilla/5.0 ({win_ver}{feature}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{br_ver} Safari/537.36',
                'Mozilla/5.0 ({win_ver}{feature}; Trident/7.0; rv:{br_ver}) like Gecko',
                'Mozilla/5.0 (compatible; MSIE {br_ver}; {win_ver}{feature}; Trident/6.0)']

    index = randrange(len(RAND_UAS))

    return RAND_UAS[index].format(win_ver=choice(WIN_VERS), feature=choice(FEATURES), br_ver=choice(BR_VERS[index]))


def agent():

    return 'Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko'


def mobile_agent():

    return 'Mozilla/5.0 (Android 4.4; Mobile; rv:18.0) Gecko/18.0 Firefox/18.0'


def ios_agent():

    return 'Mozilla/5.0 (iPhone; CPU iPhone OS 6_0 like Mac OS X) AppleWebKit/536.26 (KHTML, like Gecko) Version/6.0 Mobile/10A5376e Safari/8536.25'


def spoofer(headers=None, _agent=True, age_str=randomagent(), referer=False, ref_str=''):

    append = '|'

    if not headers:
        headers = {}

    if _agent and age_str and not headers:
        headers.update({'User-Agent': age_str})

    if referer and ref_str:
        headers.update({'Referer': ref_str})

    if headers:
        append += urlencode(headers)
    else:
        append = ''

    return append


def cfcookie(netloc, ua, timeout):
    try:
        headers = {'User-Agent': ua}

        req = urllib2.Request(netloc, headers=headers)

        try:
            urllib2.urlopen(req, timeout=int(timeout))
        except urllib2.HTTPError as response:
            result = response.read(5242880)

        jschl = re.findall('name="jschl_vc" value="(.+?)"/>', result)[0]

        init = re.findall('setTimeout\(function\(\){\s*.*?.*:(.*?)};', result)[-1]

        builder = re.findall(r"challenge-form\'\);\s*(.*)a.v", result)[0]

        decryptVal = parseJSString(init)

        lines = builder.split(';')

        for line in lines:

            if len(line) > 0 and '=' in line:

                sections = line.split('=')
                line_val = parseJSString(sections[1])
                decryptVal = int(eval(str(decryptVal) + str(sections[0][-1]) + str(line_val)))

        answer = decryptVal + len(urlparse(netloc).netloc)

        query = '%s/cdn-cgi/l/chk_jschl?jschl_vc=%s&jschl_answer=%s' % (netloc, jschl, answer)

        if 'type="hidden" name="pass"' in result:
            passval = re.findall('name="pass" value="(.*?)"', result)[0]
            query = '%s/cdn-cgi/l/chk_jschl?pass=%s&jschl_vc=%s&jschl_answer=%s' % (
                netloc, quote_plus(passval), jschl, answer
            )
            time.sleep(5)

        cookies = cookielib.LWPCookieJar()
        handlers = [urllib2.HTTPHandler(), urllib2.HTTPSHandler(), urllib2.HTTPCookieProcessor(cookies)]
        opener = urllib2.build_opener(*handlers)
        urllib2.install_opener(opener)

        try:
            req = urllib2.Request(query, headers=headers)
            urllib2.urlopen(req, timeout=int(timeout))
        except BaseException:
            pass

        cookie = '; '.join(['%s=%s' % (i.name, i.value) for i in cookies])

        return cookie
    except BaseException:
        pass


def parseJSString(s):
    try:
        offset = 1 if s[0] == '+' else 0
        val = int(eval(s.replace('!+[]', '1').replace('!![]', '1').replace('[]','0').replace('(', 'str(')[offset:]))
        return val
    except BaseException:
        pass
