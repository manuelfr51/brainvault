import unittest
from blockchain_providers import *

# this is the coinbase transaction from block 20
# early blocks are safe to test with since we can assume
# that Satoshi will not move his coins
test_address = '15ubjFzmWVvj3TqcpJ1bSsb8joJ6gF6dZa'
expected_tx = 'ee1afca2d1130676503a6db5d6a77075b2bf71382cfdf99231f89717b5257b5b'
expected_balance_res = (5000000000, 1)
expected_utxo = {
    'output': 'ee1afca2d1130676503a6db5d6a77075b2bf71382cfdf99231f89717b5257b5b:0',
    'value': 5000000000
}

class ProviderTest:

    def test_get_address_info(self):
        addr_info = self.provider.get_address_info([test_address])
        self.assertEqual(1, len(addr_info))
        self.assertEqual(expected_balance_res, addr_info[0])
        self.assertTrue(isinstance(addr_info[0][0], long))
        self.assertTrue(isinstance(addr_info[0][1], long))

    def test_get_utxo(self):
        utxo = self.provider.get_utxo(test_address)
        self.assertEqual(1, len(utxo))
        self.assertEqual(expected_utxo['output'], utxo[0]['output'])
        self.assertEqual(expected_utxo['value'], utxo[0]['value'])
        self.assertTrue(isinstance(utxo[0]['value'], long))

class BlockchainInfoProviderTest(unittest.TestCase, ProviderTest):
    @classmethod
    def setUpClass(self):
        self.provider = BlockchainInfoProvider()

class BlockrProviderTest(unittest.TestCase, ProviderTest):
    @classmethod
    def setUpClass(self):
        self.provider = BlockrProvider()

class InsightProviderTest(unittest.TestCase, ProviderTest):
    @classmethod
    def setUpClass(self):
        self.provider = InsightProvider()

class BlockCypherProviderTest(unittest.TestCase, ProviderTest):
    @classmethod
    def setUpClass(self):
        self.provider = BlockCypherProvider()

if __name__ == '__main__':
    unittest.main()
