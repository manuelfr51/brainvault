from bitcoin import *
import getpass
import json
import random
import argparse
import time
import os.path
import binascii
import readline
import platform
from . import diceware
from .blockchain_providers import *
from .aes import AES

SATOSHIS = 100000000
BTCUSD_RATE = 0
BTCUSD_FETCHED = 0
PROVIDER = None
NO_FIAT = False

class Address:
    def __init__(self, exp):
        self.exp = exp
        self.pub = privtopub(exp)
        self.addr = pubtoaddr(self.pub)
        self.priv = encode_privkey(exp, 'wif')
        self.balance = None

class TxData:
    def __init__(self, tx, chg_idx):
        self.outs = []
        self.change = None
        c_outs = deserialize(tx)['outs']
        for i,o in enumerate(c_outs):
            value = o['value']
            address = script_to_address(o['script'])
            output = (address, value)
            if i != chg_idx:
                self.outs.append(output)
            else:
                self.change = output

class Wallet:
    def __init__(self, passphrase, start_idx, end_idx, algo=0):
        self.addresses = []
        self.idx_map = {}
        self.n = 0
        self.passphrase = passphrase

        self.algo = algo
        self.passphrase = passphrase
        if algo == 0:
            exp = sha256(passphrase)
            addresses = [Address(exp)]
        elif algo == 1:
            addresses = create_address_range(passphrase, start_idx, end_idx)
        self.add_many([None for i in range(start_idx)])
        self.add_many(addresses)

    def add(self, address):
        self.addresses.append(address)
        if address is not None: self.idx_map[address.addr] = self.n
        self.n += 1

    def add_many(self, addresses):
        for a in addresses:
            self.add(a)

    def get(self, address_or_index):
        idx = -1
        if isinstance(address_or_index, int):
            idx = address_or_index if 0 <= address_or_index < len(self.addresses) else -1
        elif self.idx_map.has_key(address_or_index):
            idx = self.idx_map[address_or_index]
        if idx == -1:
            raise AddrOutOfRangeEx()
        return self.addresses[idx]

    def get_unused_addr(self):
        return next((c for c in self.addresses if c.balance is None), None)

    def expand(self, i):
        if self.algo > 0:
            addresses = create_address_range(self.passphrase, self.n, self.n+i)
            self.add_many(addresses)
        else: raise Exception('Unable to expand a singular brainwallet')

    def update_balances(self, from_idx = 0):
        global PROVIDER
        batches=[]
        batch_size = 15
        batch = []
        ind = 0

        for i, a in enumerate(self.addresses):
            if a is None or i < from_idx: continue
            batch_ind = i / batch_size
            if ind < batch_size:
                batch.append(a.addr)
                ind += 1
            if ind == batch_size - 1 or i == self.n - 1:
                batches.append(batch)
                batch = []
                ind = 0

        for batch in batches:
            addr_info = PROVIDER.get_address_info(batch)
            n_unused = 0
            for i,info in enumerate(addr_info):
                if info[1] == 0:
                    n_unused += 1
                else:
                    addr = self.get(batch[i])
                    addr.balance = info[0]
            if n_unused >= 5: break

class AddrOutOfRangeEx(Exception):
    pass

def hex_string_to_int_array(hex_string):
    result = []
    for i in range(0, len(hex_string), 2):
        result.append(int(hex_string[i:i+2], 16))
    return result

def create_address_range(passphrase, start, end):
    list = []
    for i in range(start, end):
        exp = sha256(passphrase + str(i))
        list.append(Address(exp))
        update_progress(float(i-start+1) / (end-start), 'Deriving keys')
    return list

def make_tx(address, to_address, change_address, amount, fee = None):
    global PROVIDER
    outs = []
    ins = PROVIDER.get_utxo(address.addr)
    balance = sum(i['value'] for i in ins)
    # default fee is 0.1 mBTC
    basic_fee = SATOSHIS / 10000
    if fee is None:
        txsize = len(ins)*180 + 2*34 + 10 + len(ins)
        fee = basic_fee * (1000 if txsize < 1000 else txsize) / 1000

    change_amt = 0
    if amount + fee >= balance:
        amount = balance - fee
    else:
        change_amt = balance - amount - fee
        if change_amt < 10000:
            change_amt = 0
            amount += change_amt

    payment_out = {'value': amount, 'address': to_address}
    change_out = {'value': change_amt, 'address': change_address}
    # randomize the order of change and payment to increase privacy
    outs.append(payment_out)
    chg_idx = random.randint(0,1)
    if change_amt > 0:
        outs.insert(chg_idx, change_out)
    else:
        chg_idx = -1
    tx = mktx(ins, outs)
    for i in range(0, len(ins)):
        tx = sign(tx, i, address.exp)
    return (tx, chg_idx)

def validate_tx(wallet, tx, chg_idx, from_addr, chg_address_str):
    print('')
    
    tx_data = TxData(tx, chg_idx)
    outs = tx_data.outs
    chg = tx_data.change
    chg_value = 0 if chg is None else chg[1]
    spending = sum(o[1] for o in outs)
    fee = from_addr.balance - (spending + chg_value)

    # print origin address info
    from_idx = wallet.idx_map.get(from_addr.addr)
    from_idx_str = '' if from_idx is None else '[{}]'.format(from_idx)
    print('From:   {} {}'.format(from_addr.addr, from_idx_str))

    # print output info
    for o in outs:
        to_idx = wallet.idx_map.get(o[0])
        to_idx_str = '' if to_idx is None else '[{}]'.format(to_idx)
        to_str = 'To:     ' + colorize('yellow', '{}') + ' -> {} {}'
        print(to_str.format(fmt_satoshi(o[1]), o[0], to_idx_str))

    # print change info
    chg_info = 'none'
    if chg is not None:
        chg_idx = wallet.idx_map.get(chg[0])
        chg_idx_str = '' if chg_idx is None else '[{}]'.format(chg_idx)
        chg_info = colorize('yellow', '{}') + ' -> {} {}'
        chg_info = chg_info.format(fmt_satoshi(chg[1]), chg[0], chg_idx_str)
    print('Change: ' + chg_info)

    # print fee
    print('Fee:    ' + colorize('yellow', '{}').format(fmt_satoshi(fee)))
    
    # assert that all values add up and that nothing is lost
    assert fee + spending + chg_value == from_addr.balance
    if chg_value > 0:
        assert chg[0] == chg_address_str

def send(wallet, addr_idx, to_address, amount, fee = None,
            chg_address_str = None, craft_only = False):
    
    from_addr = wallet.get(addr_idx)
    if from_addr.balance is None or from_addr.balance <= amount:
        print('Insufficient balance on the specified address.')
        return

    from_addr = wallet.addresses[addr_idx]
    chg_address = wallet.get_unused_addr()
    if chg_address_str is None:
        chg_address_str = from_addr.addr if chg_address is None else chg_address.addr

    #address format validation
    try:
        b58check_to_bin(to_address)
        b58check_to_bin(chg_address_str)
    except:
        print('Invalid destination or change address.')
        return

    tx, chg_idx = make_tx(from_addr, to_address, chg_address_str, amount, fee)
    validate_tx(wallet, tx, chg_idx, from_addr, chg_address_str)

    if craft_only:
        print(tx)
    elif prompt_bool('Proceed?'):
        global PROVIDER
        push_res = PROVIDER.pushtx(tx)
        if (push_res[0]):
            print('Transaction pushed.\ntxhash: %s' % txhash(tx))
        else:
            print('Push error: ' + push_res[1])
    else:
        print('Transaction aborted.')

def sweep(wallet, priv, to_addr_idx = None):
    
    global PROVIDER

    try:
        exp = b58check_to_hex(priv)
    except:
        print('Not a valid private key.')
        return

    from_address = Address(exp)
    from_address.balance = PROVIDER.get_address_info([from_address.addr])[0][0]

    if to_addr_idx is not None:
        to_address = wallet.get(to_addr_idx).addr
    else:
        unused_address = wallet.get_unused_addr()
        if unused_address is None:
            print('No free addresses')
            return
        else:
            to_address = unused_address.addr

    tx, chg_idx = make_tx(from_address, to_address, None, from_address.balance)
    validate_tx(wallet, tx, None, from_address, None)

    if prompt_bool('Proceed?'):
        push_res = PROVIDER.pushtx(tx)
        if (push_res[0]):
            print('Transaction pushed.\ntxhash: %s' % txhash(tx))
        else:
            print('Push error: ' + push_res[1])
    else:
        print('Sweeping aborted.')

def print_wallet(wallet, show_spent = False, show_unused_n = 5):
    n_unused = 0
    print('\n#\taddress\t\t\t\t\tUSD\t\tBTC')
    total = 0
    for i, a in enumerate(wallet.addresses):
        if a is None:
            pass
        else:
            balance_str = 'N/A'
            fiat_str = 'N/A'
            if a.balance == 0 and not show_spent:
                continue
            if a.balance is not None:
                total += a.balance
                balance_str = fmt_satoshi(a.balance)
                fiat_str = '{0:.2f}'.format(to_usd(balance_str))
            else:
                n_unused += 1
            print('{}\t{}\t{}\t{}'.format(i, a.addr, fiat_str.ljust(10), balance_str))
        if n_unused >= show_unused_n: break

    print(72 * '-') 
    usd_total = '{:.2f}'.format(to_usd(fmt_satoshi(total))).ljust(10)
    print('TOTAL: \t\t\t\t\t\t{}\t{}'.format(usd_total, fmt_satoshi(total)))

def sign_text(address):
    print('Enter the message to sign. End with a newline.\n')
    text = raw_input()
    sig = ecdsa_sign(text, address.priv)
    print(sig)

def display_help(cmds):
    print('Type [command] -h to display help for a command.')
    print('Available commands:')
    for key in cmds:
        print(key)

def refresh_wallet(wallet):
    wallet.update_balances()

def fmt_satoshi(value):
    return (float(value) / SATOSHIS)

def save_ph_to_file(filename, ph):
    key = getpass.getpass('Encryption key:')
    aes = AES(key)
    iv_hex = ''.join('{:02x}'.format(i) for i in aes.get_iv_str())
    ph_hex = ''.join('{:02x}'.format(i) for i in aes.encrypt(ph))
    f = open(filename, 'w')
    f.write(iv_hex + ph_hex)
    f.close()
    print('File saved succesfully.')

def get_ph_from_file(filename):
    f = open(filename, 'r')
    in_data = f.readline().strip()
    f.close()
    key = getpass.getpass('Decryption key:')
    iv_bytes = hex_string_to_int_array(in_data[0:64])
    ph_bytes = hex_string_to_int_array(in_data[64:])
    aes = AES(key, iv_bytes)
    ph = ''.join(chr(i) for i in aes.decrypt(ph_bytes) if i > 31)
    return ph

def prompt_bool(question):
    res = False
    while True:
        val = raw_input(question + ' (y/n)').lower()
        if val == 'y' or val == 'n':
            res = val == 'y'
            break
        else:
            print("Error. Only y/n values are allowed.")
    return res

def to_usd(amount):
    global NO_FIAT, BTCUSD_RATE, BTCUSD_FETCHED
    if NO_FIAT:
        return 0
    if amount is None: amount = 0
    # caching the exchange rate for 5 minutes
    if BTCUSD_RATE == 0 or BTCUSD_FETCHED + 300 < time.time():
        try:
            resp = make_request('https://api.bitcoinaverage.com/ticker/global/USD/')
            jsonobj = json.loads(resp)
            BTCUSD_RATE = jsonobj['last']
            BTCUSD_FETCHED = time.time()
        except Exception as e:
            pass
    return amount * BTCUSD_RATE

def build_commands():
    sendcmd = argparse.ArgumentParser(prog='send', description=
                                        'Send bitcoins to a destination address.')
    sendcmd.add_argument('idx', metavar = 'IDX', type=int,
                            help='Index of the address to send from')
    sendcmd.add_argument('dest', metavar = 'DESTINATION', help = 'Destination address')
    sendcmd.add_argument('amount', metavar = 'AMOUNT', type=float,
                            help='Amount of BTC to send')
    sendcmd.add_argument('-f', '--fee', help='Transaction fee', type=float, default = None)
    sendcmd.add_argument('-c', '--changeAddress', help='Change address')
    sendcmd.add_argument('-m', '--makeOnly', action='store_true',
                            help='Only craft a tx and print it out without sending')

    listcmd = argparse.ArgumentParser(prog='list', description=
                                        'List currently generated addresses.')
    listcmd.add_argument('-u', '--unused', type=int,
                            help='Cut off printing at n unused addresses', default=5)
    listcmd.add_argument('-s', '--showSpent', action='store_true',
                            help='Show used/spent addresses', default=False)

    exitcmd = argparse.ArgumentParser(prog='exit', description='Exits the program.')

    sweepcmd = argparse.ArgumentParser(prog='sweep', description=
                                        'Sweep an exiting private key into an existing address.')
    sweepcmd.add_argument('priv', metavar = 'PRIVKEY',
                            help = 'Private key to sweep (WIF format).')
    sweepcmd.add_argument('-i', '--index', type=int, help=('Index of an existing address to sweep into.'
                            'If not specified, funds are swept into the first unused address.'))

    refreshcmd = argparse.ArgumentParser(prog='refresh', description=
                                        'Refreshes the wallet and balances.')

    expandcmd = argparse.ArgumentParser(prog='expand', description=
                                        'Expands a deterministic wallet by N entries.')
    expandcmd.add_argument('n', metavar = 'N', help = 'Number of addresses to expand by.',
                            type=int, default = 5)

    savepasscmd = argparse.ArgumentParser(prog='save', description=
                                        'Encrypts the passphrase with AES and saves it to a file.')
    savepasscmd.add_argument('-f', '--filename', default = 'key.txt', help = 'Custom file name')

    dumpprivcmd = argparse.ArgumentParser(prog='dumppriv', description=
                                            'Shows the private key for the specified index.')
    dumpprivcmd.add_argument('idx', metavar = 'IDX', type=int, help = 'Address index')

    helpcmd = argparse.ArgumentParser(prog='help', description='Displays help')

    signcmd = argparse.ArgumentParser(prog='sign', description='Reads a plaintext and signs it.')
    signcmd.add_argument('idx', metavar = 'IDX', type=int,
                            help='Index of the address whose private key to sign with')

    cmds = {}
    cmds['send'] = sendcmd
    cmds['list'] = listcmd
    cmds['exit'] = exitcmd
    cmds['refresh'] = refreshcmd
    cmds['sweep'] = sweepcmd
    cmds['expand'] = expandcmd
    cmds['save'] = savepasscmd
    cmds['dumppriv'] = dumpprivcmd
    cmds['help'] = helpcmd
    cmds['sign'] = signcmd
    return cmds

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-r', '--range', default=25,
                        help=('Range of address indexes if using a deterministic wallet.'
                                'One number will generate n iterations starting from 0, '
                                'while n-m format will generate a specific range of iterations.'))
    parser.add_argument('-a', '--algorithm', choices=[0,1], type=int,
                        default='1', help = '''Wallet generation algorithm.
                        0 - single brainwallet.
                        1 - type 1 deterministic wallet.'''
                        )
    parser.add_argument('-d', '--dataProvider', choices=['blockchaininfo', 'blockr', 'insight', 'blockcypher'],
                        default='blockchaininfo', help='Data provider for the wallet')
    parser.add_argument('-n', '--noFiat', action='store_true',
                        default=False, help='Turns off fiat conversion')
    parser.add_argument('-f', '--file', help='Reads the passphrase from an AES encrypted file.')
    parser.add_argument('-w', '--diceware', action='store_true',
                        default=False, help='The passphrase is interpreted as a series of diceware numbers')
    parser.add_argument('-o', '--offline', action='store_true',
                        default=False, help='Whether to immediately fetch address balances online')
    parser.add_argument('-u', '--url', help='''Set a custom hostname for the selected data provider.
                                            The format should be e.g. http[s]://url.com[:80].
                                            Useful for open source block explorers that exist in different
                                            locations but have identical operation contracts.''')
    args = parser.parse_args()

    start_idx = 0
    end_idx = 1
    try:
        end_idx = int(args.range)
    except:
        try:
            rng = args.range.split('-')
            assert len(rng) == 2
            start_idx = int(rng[0])
            end_idx = int(rng[1])
        except:
            print('Range parameter should be an integer or a range of values in the n-m format.')
            exit()

    global NO_FIAT, PROVIDER
    PROVIDER = get_provider_by_name(args.dataProvider)
    NO_FIAT = args.noFiat

    if args.url is not None:
        PROVIDER.host = args.url.strip().strip('/')
    print('Data provider: {}, host: {}'.format(
        colorize('yellow', PROVIDER.name()),
        colorize('yellow', PROVIDER.host)))

    ph = None
    filename = None
    if args.file is None and os.path.isfile('key.txt'):
        filename = 'key.txt'
    elif args.file is not None:
            if os.path.isfile(args.file):
                filename = args.file
            else:
                print('Could not find the specified file. Enter passphrase manually.')

    if filename is not None:
        print('Decrypting file and extracting passphrase...')
        try:
            ph = get_ph_from_file(filename)
        except IOError:
            print('Could not decrypt the file.')
            return
    else:
        ph = getpass.getpass('Seed:')
        if args.diceware is True:
            diceware_dict = diceware.load_diceware()
            ph = diceware.to_string(ph, diceware_dict)

    wallet = Wallet(ph, start_idx, end_idx, args.algorithm)

    if args.offline:
        print('\nWARNING: wallet operating offline')
    else:
        wallet.update_balances()

    print('Used addressess with a balance of zero BTC are hidden.\n'
            'Use list -s to show such addresses.\n')
    print_wallet(wallet)

    cmds = build_commands()

    print("Type 'help' to display available commands")

    while True:
        try:
            if not input_loop(cmds, wallet):
                break
        except AddrOutOfRangeEx:
            print('The specified address index is out of generated range. '
                    'Use the expand command to generate more addresses.')
        except Exception as e:
            print('Error:')
            print(e)

    del(ph)
    del(wallet)
    cls()

def input_loop(cmds, wallet):
    input = raw_input('> ').strip()
    c = input.split(' ', 1)[0]
    if c == '':
        return True
    cmd = cmds.get(c)
    if cmd is None:
        print('No such command. Type help to see available commands')
        return True
    cmd_args = None
    try:
        cmd_args = cmd.parse_args(input.split()[1:])
    except SystemExit:
        return True
    if c == 'send':
        send(   wallet, cmd_args.idx, cmd_args.dest,
                int(cmd_args.amount * SATOSHIS),
                int(cmd_args.fee * SATOSHIS) if cmd_args.fee is not None else None,
                cmd_args.changeAddress,
                cmd_args.makeOnly)
    elif c == 'help':
        display_help(cmds)
    elif c == 'list':
        print_wallet(wallet, cmd_args.showSpent, cmd_args.unused)
    elif c == 'refresh':
        refresh_wallet(wallet)
    elif c == 'sweep':
        sweep(wallet, cmd_args.priv, cmd_args.index)
    elif c == 'q' or c == 'quit' or c == 'exit':
        return False
    elif c == 'expand':
        wallet.expand(cmd_args.n)
        refresh_wallet(wallet)
    elif c == 'save':
        save_ph_to_file('key.txt', wallet.passphrase)
    elif c == 'dumppriv':
        print(wallet.get(cmd_args.idx).priv)
    elif c == 'sign':
        sign_text(wallet.get(cmd_args.idx))
    elif c == 'exit':
        return False
    return True

def cls():
    from subprocess import call
    system = platform.system()
    if system == 'Linux':
        call('reset', shell = True)
    elif system == 'Windows':
        call('cls', shell = True)

def update_progress(progress, text):
    barLength = 20
    status = ""
    if progress < 0:
        progress = 0
        status = "Halt...\n"
    if progress >= 1:
        progress = 1
        status = "Done...\n"
    block = int(round(barLength*progress))
    text = "\r" + text + ": [{0}] {1:.0f}% {2}".format(
        "|"*block + "-"*(barLength-block), progress*100, status)
    sys.stdout.write(text)
    sys.stdout.flush()

def colorize(color, text):
    system = platform.system() 
    if system != 'Linux':
        return text
    else:
        colors = {
            'header': '\033[95m',
            'blue': '\033[94m',
            'green': '\033[92m',
            'yellow': '\033[93m',
            'fail': '\033[91m',
            'end': '\033[0m',
            'bold': '\033[1m',
            'underline': '\033[4m',
        }
        return colors[color] + text + colors['end']

if __name__ == "__main__":
    main()
