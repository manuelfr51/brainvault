from bitcoin.main import *
from bitcoin.transaction import *
from bitcoin.deterministic import *
from bitcoin.blocks import *

# BIP32 hierarchical deterministic multisig script
def bip32_hdm_script(*args):
    if len(args) == 3:
        keys, req, path = args
    else:
        i, keys, path = 0, [], []
        while len(args[i]) > 40:
            keys.append(args[i])
            i += 1
        req = int(args[i])
        path = map(int, args[i+1:])
    pubs = sorted(map(lambda x: bip32_descend(x, path), keys))
    return mk_multisig_script(pubs, req)


# BIP32 hierarchical deterministic multisig address
def bip32_hdm_addr(*args):
    return scriptaddr(bip32_hdm_script(*args))

# Inspects a transaction
def inspect(tx, **kwargs):
    d = deserialize(tx)
    isum = 0
    ins = {}
    for _in in d['ins']:
        h = _in['outpoint']['hash']
        i = _in['outpoint']['index']
        prevout = deserialize(fetchtx(h, **kwargs))['outs'][i]
        isum += prevout['value']
        a = script_to_address(prevout['script'])
        ins[a] = ins.get(a, 0) + prevout['value']
    outs = []
    osum = 0
    for _out in d['outs']:
        outs.append({'address': script_to_address(_out['script']),
                     'value': _out['value']})
        osum += _out['value']
    return {
        'fee': isum - osum,
        'outs': outs,
        'ins': ins
    }


def merkle_prove(txhash):
    blocknum = str(get_block_height(txhash))
    header = get_block_header_data(blocknum)
    hashes = get_txs_in_block(blocknum)
    i = hashes.index(txhash)
    return mk_merkle_proof(header, hashes, i)
