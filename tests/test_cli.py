#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sat Jan 15 13:36:18 2022

@author: mvr
"""
import unittest
import subprocess
import os

class Test_Cases_Rfc8554(unittest.TestCase):
    def test_case_1(self):
        ret = subprocess.run(['hsslms', 'verify', '-k', 'test_case_1_pubkey.bin', '-m', 'test_case_1_message.bin', '-s', 'test_case_1_signature.bin'], capture_output=True)
        self.assertEqual(ret.returncode, 0, "Test Case 1: Verification failed.")
        ret = subprocess.run(['hsslms', 'verify', '-k', 'test_case_1_pubkey.bin', '-m', 'test_case_2_message.bin', '-s', 'test_case_1_signature.bin'], capture_output=True)
        self.assertEqual(ret.returncode, 1, "Test Case 1: Verification not failed.")
        ret = subprocess.run(['hsslms', 'verify', '-k', 'test_case_1_pubkey.bin', '-m', 'test_case_1_message.bin', '-s', 'test_case_2_signature.bin'], capture_output=True)
        self.assertEqual(ret.returncode, 1, "Test Case 1: Verification not failed.")
        
    def test_case_2(self):
        ret = subprocess.run(['hsslms', 'verify', '-k', 'test_case_2_pubkey.bin', '-m', 'test_case_2_message.bin', '-s', 'test_case_2_signature.bin'], capture_output=True)
        self.assertEqual(ret.returncode, 0, "Test Case 2: Verification failed.")
        ret = subprocess.run(['hsslms', 'verify', '-k', 'test_case_2_pubkey.bin', '-m', 'test_case_1_message.bin', '-s', 'test_case_2_signature.bin'], capture_output=True)
        self.assertEqual(ret.returncode, 1, "Test Case 2: Verification not failed.")
        ret = subprocess.run(['hsslms', 'verify', '-k', 'test_case_2_pubkey.bin', '-m', 'test_case_2_message.bin', '-s', 'test_case_1_signature.bin'], capture_output=True)
        self.assertEqual(ret.returncode, 1, "Test Case 2: Verification not failed.")

class Test_H5(unittest.TestCase):
    def test(self):
        ret = subprocess.run(['hsslms', 'key-gen', '--lmots', 'LMOTS_SHA256_N32_W2', '--lms', 'LMS_SHA256_M32_H5', '-o', 'testkey', '-p', 'abc'], capture_output=True)
        self.assertEqual(ret.returncode, 0, "H5: Key Generation failed.")
        ret = subprocess.run(['hsslms', 'sign', '-k', 'testkey', '-m', 'test_case_1_message.bin', '-s', 'test_signature', '-p', 'abc'], capture_output=True)
        self.assertEqual(ret.returncode, 0, "H5: Signature Generation failed.")
        ret = subprocess.run(['hsslms', 'verify', '-k', 'testkey.pub', '-m', 'test_case_1_message.bin', '-s', 'test_signature'], capture_output=True)
        self.assertEqual(ret.returncode, 0, "H5: Verification failed.")
        # exhaust private key
        for _ in range(2**5-1):
            os.remove('test_signature')
            ret = subprocess.run(['hsslms', 'sign', '-k', 'testkey', '-m', 'test_case_1_message.bin', '-s', 'test_signature', '-p', 'abc'], capture_output=True)
            self.assertEqual(ret.returncode, 0, "H5: Signature Generation failed.")
            ret = subprocess.run(['hsslms', 'verify', '-k', 'testkey.pub', '-m', 'test_case_1_message.bin', '-s', 'test_signature'], capture_output=True)
            self.assertEqual(ret.returncode, 0, "H5: Verification failed.")
        os.remove('test_signature')
        ret = subprocess.run(['hsslms', 'sign', '-k', 'testkey', '-m', 'test_case_1_message.bin', '-s', 'test_signature', '-p', 'abc'], capture_output=True)
        self.assertEqual(ret.returncode, 1, "H5: Signature Generation not failed.")
        os.remove('testkey')
        os.remove('testkey.pub')

class Test_H5H10(unittest.TestCase):
    def test(self):
        ret = subprocess.run(['hsslms', 'key-gen', '--lmots', 'LMOTS_SHA256_N32_W2', '--lms', 'LMS_SHA256_M32_H5', 'LMS_SHA256_M32_H10', '-o', 'testkey', '-p', 'abc'], capture_output=True)
        self.assertEqual(ret.returncode, 0, "H5H10: Key Generation failed.")
        ret = subprocess.run(['hsslms', 'sign', '-k', 'testkey', '-m', 'test_case_1_message.bin', '-s', 'test_signature', '-p', 'abc'], capture_output=True)
        self.assertEqual(ret.returncode, 0, "H5H10: Signature Generation failed.")
        ret = subprocess.run(['hsslms', 'verify', '-k', 'testkey.pub', '-m', 'test_case_1_message.bin', '-s', 'test_signature'], capture_output=True)
        self.assertEqual(ret.returncode, 0, "H5H10: Verification failed.")
        os.remove('testkey')
        os.remove('testkey.pub')
        os.remove('test_signature')


class Test_H10H5(unittest.TestCase):
    def test(self):
        ret = subprocess.run(['hsslms', 'key-gen', '--lmots', 'LMOTS_SHA256_N32_W2', '--lms', 'LMS_SHA256_M32_H10', 'LMS_SHA256_M32_H5', '-o', 'testkey', '-p', 'abc'], capture_output=True)
        self.assertEqual(ret.returncode, 0, "H10H5: Key Generation failed.")
        ret = subprocess.run(['hsslms', 'sign', '-k', 'testkey', '-m', 'test_case_1_message.bin', '-s', 'test_signature', '-p', 'abc'], capture_output=True)
        self.assertEqual(ret.returncode, 0, "H10H5: Signature Generation failed.")
        ret = subprocess.run(['hsslms', 'verify', '-k', 'testkey.pub', '-m', 'test_case_1_message.bin', '-s', 'test_signature'], capture_output=True)
        self.assertEqual(ret.returncode, 0, "H10H5: Verification failed.")
        os.remove('testkey')
        os.remove('testkey.pub')
        os.remove('test_signature')


if __name__ == '__main__':
    unittest.main()
