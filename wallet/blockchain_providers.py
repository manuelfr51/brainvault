import json, re
import random
import sys
try:
    from urllib.request import build_opener
except:
    from urllib2 import build_opener

SATOSHIS = 100000000

def get_provider_by_name(name):
    if name == 'blockchaininfo':
        return BlockchainInfoProvider()
    if name == 'blockr':
        return BlockrProvider()
    if name == 'insight':
        return InsightProvider()
    if name == 'blockcypher':
        return BlockCypherProvider()
    raise Exception('No such data provider')

class DataProvider:

    def get_address_info(self, addresses):
        raise Exception('Unimplemented')

    def get_utxo(self, address):
        raise Exception('Unimplemented')

    def pushtx(self, tx):
        error = None
        try:
            self.pushtx_impl(tx)
        except Exception as e:
            error = e.message
        return (True if error is None else False, error)

    def name(self):
        raise Exception('Unimplemented')

    def pushtx_impl(self, tx):
        raise Exception('Unimplemented')

class BlockchainInfoProvider(DataProvider):

    def __init__(self):
        self.host = 'https://blockchain.info'

    def get_address_info(self, addresses):
        endpoint = self.host + '/multiaddr?active='
        resp = make_request(endpoint + '|'.join(addresses) + '&offset=10000')
        jsonobj =  json.loads(resp.decode("utf-8"))
        addr_info = [(0, 0) for a in addresses]
        for a in jsonobj['addresses']:
            addr_str = a['address']
            idx = addresses.index(addr_str)
            addr_info[idx] = (long(a['final_balance']), long(a['n_tx']))
        return addr_info

    def get_utxo(self, address):
        endpoint = self.host + '/unspent?active='
        resp = make_request(endpoint + address)
        jsonobj = json.loads(resp.decode('utf-8'))
        outs = []
        for o in jsonobj['unspent_outputs']:
            h = o['tx_hash'].decode('hex')[::-1].encode('hex')
            outs.append({
                'output': h+':'+str(o['tx_output_n']),
                'value': long(o['value'])
            })
        return outs

    def pushtx_impl(self, tx):
        make_request(self.host + '/pushtx', 'tx='+tx)

    def name(self):
        return 'BlockchainInfo'

class BlockrProvider(DataProvider):

    def __init__(self):
        self.host = 'https://btc.blockr.io'

    def get_address_info(self, addresses):
        endpoint = self.host + '/api/v1/address/info/'
        resp = make_request(endpoint + ','.join(addresses) + '?offset=10000')
        jsonobj = json.loads(resp.decode('utf-8'))
        addr_info = [(0, 0) for a in addresses]
        addr_data = jsonobj['data']
        if isinstance(addr_data, dict):
            addr_data = [addr_data]
        for a in addr_data:
            addr_str = a['address']
            idx = addresses.index(addr_str)
            balance = long(float(a['balance']) * SATOSHIS)
            addr_info[idx] = (balance, long(a['nb_txs']))
        return addr_info

    def get_utxo(self, address):
        endpoint = self.host + '/api/v1/address/unspent/'
        resp = make_request(endpoint + address)
        jsonobj = json.loads(resp.decode('utf-8'))
        outs = []
        utxo_data = jsonobj['data']['unspent']
        for o in utxo_data:
            outs.append({
                'output': o['tx'] + ':' + str(o['n']),
                'value': long(float(o['amount']) * SATOSHIS)
            })
        return outs

    def pushtx_impl(self, tx):
        make_request(self.host + '/api/v1/tx/push', '{"hex":"%s"}' % tx)

    def name(self):
        return 'Blockr'

class InsightProvider(DataProvider):

    def __init__(self):
        self.host = 'https://insight.bitpay.com'

    def get_address_info(self, addresses):
        # possibly slow since insight doesn't support multiaddr queries
        endpoint = self.host + '/api/addr/{}?noTxList=1'
        addr_info = [(0, 0) for a in addresses]
        for a in addresses:
            resp = make_request(endpoint.format(a))
            jsonobj = json.loads(resp.decode('utf-8'))
            idx = addresses.index(jsonobj['addrStr'])
            addr_info[idx] = (
                long(jsonobj['balanceSat']),
                long(jsonobj['txApperances']))
        return addr_info

    def get_utxo(self, address):
        endpoint = self.host + '/api/addr/{}/utxo'
        resp = make_request(endpoint.format(address))
        jsonobj = json.loads(resp.decode('utf-8'))
        outs = []
        for o in jsonobj:
            outs.append({
                'output': o['txid'] + ':' + str(o['vout']),
                'value': long(float(o['amount']) * SATOSHIS)
            })
        return outs

    def pushtx_impl(self, tx):
        make_request(self.host + '/api/tx/send', 'rawtx='+tx)

    def name(self):
        return 'Insight'

class BlockCypherProvider(DataProvider):

    def __init__(self):
        self.host = 'https://api.blockcypher.com'

    def get_address_info(self, addresses):
        # possibly slow since BlockCypher doesn't support multiaddr queries
        endpoint = self.host + '/v1/btc/main/addrs/{}/balance'
        addr_info = [(0, 0) for a in addresses]
        for a in addresses:
            resp = make_request(endpoint.format(a))
            jsonobj = json.loads(resp.decode('utf-8'))
            idx = addresses.index(jsonobj['address'])
            addr_info[idx] = (long(jsonobj['balance']), long(jsonobj['n_tx']))
        return addr_info

    def get_utxo(self, address):
        endpoint = self.host + '/v1/btc/main/addrs/{}?unspentOnly=true'
        resp = make_request(endpoint.format(address))
        jsonobj = json.loads(resp.decode('utf-8'))
        outs = []
        for o in jsonobj['txrefs']:
            outs.append({
                'output': o['tx_hash'] + ':' + str(o['tx_output_n']),
                'value': long(o['value'])
            })
        return outs

    def pushtx_impl(self, tx):
        endpoint = self.host + '/v1/bcy/test/txs/push'
        make_request(endpoint, '{"tx":"%s"}' % tx)

    def name(self):
        return 'BlockCypher'

def make_request(*args):
    opener = build_opener()
    opener.addheaders = [('User-agent', USER_AGENT)]
    try:
        return opener.open(*args).read().strip()
    except Exception as e:
        try:
            p = e.read().strip()
        except:
            p = e
        raise Exception(p)


user_agents = [
    'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_4) AppleWebKit/601.5.17 (KHTML, like Gecko) Version/9.1 Safari/601.5.17',
    'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:45.0) Gecko/20100101 Firefox/45.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:45.0) Gecko/20100101 Firefox/45.0',
    'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.94 Safari/537.36',
    'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.94 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.86 Safari/537.36',
    'Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36',
    'Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.11; rv:45.0) Gecko/20100101 Firefox/45.0',
]

USER_AGENT = 'Mozilla/4.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/5.0)'
#USER_AGENT = random.choice(user_agents)

