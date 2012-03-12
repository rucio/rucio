# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Angelos Molfetas, <angelos.molfetas@cern.ch>, 2012

import unittest
from random import randint
from common import return_random_datasets as random_dsts


class TestReturnRandomDatasets(unittest.TestCase):
    """ Tests the return_random_dataset function """
    def setUp(self):
        self.num = randint(1, 10)

    def test_valid(self):
        """ Tests function with valid parameter """
        self.random_list = random_dsts(self.num)               # Ask for a random number of datasets
        self.assertIsInstance(self.random_list, list)          # Check to see if returned object is a list
        self.assertEqual(len(self.random_list), self.num)      # Test number of datasets returned is correct

        for i in range(self.num):                              # For each tuple in list:
            self.assertIsInstance(self.random_list[i], tuple)  # - Test to see that each element of list is a tuple
            self.assertEqual(len(self.random_list[i]), 2)      # - and that each tuple has two elements
            for item in self.random_list[i]:                   # For each element in tuple:
                self.assertIsInstance(item, str)               # - Check to see that it is a string

    def test_invalid(self):
        """ Tests function with invalid parameter """
        self.assertRaises(TypeError, random_dsts, 0)           # It does not make sense to return 0 datasets
        self.assertRaises(TypeError, random_dsts, None)        # This does not make sense as well
        self.assertRaises(TypeError, random_dsts, False)       # This does not make sense either

if __name__ == '__main__':
    unittest.main()
