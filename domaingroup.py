import socket
import pyotp
import json
import requests
from urllib.error import HTTPError
import argparse
import getpass
import re
import logging
log = logging.getLogger(__name__)
#logging.basicConfig(level=logging.DEBUG)
log.setLevel(level=logging.DEBUG)

import http.client
http.client.HTTPConnection.debuglevel = 0
requests.packages.urllib3.disable_warnings()

class Secret:
    
    DEFAULT = 'No Secret'

    def __init__(self, value):
        if value == Secret.DEFAULT:
            value = getpass.getpass('OTP Secret: ')
        self.value = value

    def __str__(self):
        return self.value


class UniFi:
    
    def __init__(self, ip, username, password, secret=None, port=443):
        self.ip = ip
        self.port = port
        self.username = username
        self.password = password
        self.totp = pyotp.TOTP(str(secret)) if secret else None
        self.auth = False
        self.base = 'https://'+ip+':'+str(port)
        self.browser = requests.Session()
        self.browser.headers.update({'Content-Type': 'application/json'})
        
    def process_response(self, response):
        if 'X-CSRF-Token' in response.headers:
            csrf = response.headers['X-CSRF-Token']
            self.browser.headers.update({'X-CSRF-Token': csrf})
        if('json' in response.headers['Content-Type']):
            response = response.json()
            if 'meta' in response and response['meta']['rc'] == 'ok' and 'data' in response:
                response = response['data']
        return response
    
    def page(self, url, data=None, headers=None, method='GET'):
        log.debug('getting page '+url)
        if not self.auth:
            self.login()
        url = self.base+url if not url.startswith('http') else url
        if data:
            data = json.dumps(data)
            data = data.encode()
            method = 'POST' if 'GET' == method else method
        if headers:
            self.browser.headers.update(headers)
        self.browser.headers.update({'Referer': url, 'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.3 Safari/605.1.15'})
        try:
            response = self.browser.request(method, url, data=data, verify=False, allow_redirects=True)
            if response.status_code == requests.codes.ok:
                response = self.process_response(response)
        except HTTPError as error:
            response_status = error.code # 404, 500, etc
        return response

    def login(self):
        self.auth = True # temporarily
        otp = '|'+str(self.totp.now()) if self.totp else ''
        data = {
            'username': self.username, 
            'password': self.password+otp
        }
        self.page("/")
        headers = {'Referer': self.base}
        url = "/api/auth/login"
        response = self.page(url, data=data, headers=headers)
        self.auth = False if 'unique_id' not in response else True


def get_ips_by_dns_lookup(target, port=None):
    '''
        this function takes the passed target and optional port and does a dns
        lookup. it returns the ips that it finds to the caller.

        :param target:  the URI that you'd like to get the ip address(es) for
        :type target:   string
        :param port:    which port do you want to do the lookup against?
        :type port:     integer
        :returns ips:   all of the discovered ips for the target
        :rtype ips:     list of strings
    '''
    if not port:
        port = 443
    log.debug("getting ips for "+target)
    return list(map(lambda x: x[4][0], socket.getaddrinfo('{}.'.format(target),port,type=socket.SOCK_STREAM)))

def get_domains(unifi, url):
    html = unifi.page(url).text
    domains = re.findall(r'\<(link|script|style).+?(src|href)=[\'\"].*?//([^/\"\']+)', html)
    domains.extend(re.findall(r'(\@import).*?([\'\"]).*?//([^/\"\']+)', html))
    domains = list(map(lambda x: x[2], domains))
    print("got domains for "+url+" : "+str(domains))
    return domains

def get_rules():
    f = open('rules.json')
    result = json.load(f)
    f.close()
    return result

def get_rules_ips(unifi, rules):
    result = {}
    for name in rules:
        ex_domains = []
        for domain in rules[name]:
            if domain.endswith('.'):
                domain = domain[:-1]
                ex_domains.extend(get_domains(unifi, 'https://'+domain))
            ex_domains.append(domain)
        ips = []
        ex_domains = list(set(ex_domains))
        for domain in ex_domains:
            if re.match(r'^\d+\.\d+\.\d+\.\d+.*$', domain):
                ips.append(domain)
            else:
                ips.extend(get_ips_by_dns_lookup(domain))
        result[name] = ips
    return result    

    

# build argument parser to parse script args and collect their
# values
parser = argparse.ArgumentParser()
parser.add_argument('-i', '--ip', default=None)
parser.add_argument('-u', '--username', default=None)
parser.add_argument('-p', '--password', default=None)
parser.add_argument('-s', '--secret', nargs='?', type=Secret, default=Secret.DEFAULT)
args = parser.parse_args()

secret = '' if str(args.secret) == str(Secret.DEFAULT) else str(args.secret)
unifi = UniFi(args.ip, args.username, args.password, secret)
rules = unifi.page('/proxy/network/api/s/default/rest/firewallgroup')
new_ips = get_rules_ips(unifi, get_rules())
#print(rules)

for rule in rules:
    name = rule['name']
    old_list = set(rule['group_members'])
    if name in new_ips and new_ips[name]:
        rule['group_members'].extend(new_ips[name])
        new_list = set(rule['group_members'])
        if new_list != old_list:
            rule['group_members'] = list(new_list)
            result = unifi.page('/proxy/network/api/s/default/rest/firewallgroup/'+rule['_id'], method='PUT', data=rule)
            print(name,': ',list(new_list.difference(old_list)))


