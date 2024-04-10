#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sat Jan  1 11:48:07 2022

@author: mvr
"""
from enum import Enum
from hashlib import sha256

class INVALID(Exception):
    """Exception for an invalid signature."""
    pass

class FAILURE(Exception):
    """Exception for general technical failures , e.g. if no private key is left to sign."""
    pass

def u32str(i):
    return i.to_bytes(4, 'big')

def u16str(i):
    return i.to_bytes(2, 'big')

def u8str(i):
    return i.to_bytes(1, 'big')

def strTou32(S):
    return int.from_bytes(S, 'big')

def coef(S, i, w):
    return (2**w - 1) & (S[(i*w) >> 3] >> (8 - (w * (i % (8 // w)) + w))) 

def cksm(S, w, n, ls):
    return u16str(((2**w - 1)*((n*8)//w) - sum([coef(S,i,w) for i in range((n*8)//w)])) << ls)
    

D_PBLC = u16str(0x8080)
D_MESG = u16str(0x8181)
D_LEAF = u16str(0x8282)
D_INTR = u16str(0x8383)


class LMOTS_ALGORITHM_TYPE(Enum):
    """Enumeration of Leighton-Micali One-Time-Signatures (LMOTS) algorithm types, see rfc8554.
    
    Attributes:
        H: Hashfunction
        n (int): Outputlength of the hashfunction
        w (int): number of simultanious signes bits
        p (int): internal dependent parameter
        ls (int): internal dependent parameter
    """
    LMOTS_SHA256_N32_W1  = 1
    LMOTS_SHA256_N32_W2  = 2
    LMOTS_SHA256_N32_W4  = 3
    LMOTS_SHA256_N32_W8  = 4
    
    LMOTS_SHA256_N24_W1  = 5
    LMOTS_SHA256_N24_W2  = 6
    LMOTS_SHA256_N24_W4  = 7
    LMOTS_SHA256_N24_W8  = 8

    @property
    def H(self):
        return sha256
    @property
    def n(self):
        if 'N32' in self.name:
            return 32
        else:
            return 24
    @property
    def w(self):
        return {1:1, 2:2, 3:4, 4:8, 5:1, 6:2, 7:4, 8:8}[self.value]
    @property
    def p(self):
        return {1:265, 2:133, 3:67, 4:34, 5:200, 6:101, 7:51, 8:26}[self.value]
    @property
    def ls(self):
        return {1:7, 2:6, 3:4, 4:0, 5:8, 6:6, 7:4, 8:0}[self.value]


class LMS_ALGORITHM_TYPE(Enum):
    """Enumeration of Leighton-Micali Signatures (LMS) algorithm types, see rfc8554.
    
    Attributes:
        H: Hashfunction
        m (int): Outputlength of the hashfunction
        h (int): height of the tree
    """
    LMS_SHA256_M32_H5  = 5
    LMS_SHA256_M32_H10 = 6
    LMS_SHA256_M32_H15 = 7
    LMS_SHA256_M32_H20 = 8
    LMS_SHA256_M32_H25 = 9

    LMS_SHA256_M24_H5 = 10
    LMS_SHA256_M24_H10 = 11
    LMS_SHA256_M24_H15 = 12
    LMS_SHA256_M24_H20 = 13
    LMS_SHA256_M24_H25 = 14

    @property
    def H(self):
        return sha256

    @property
    def m(self):
        if 'M32' in self.name:
            return 32
        else:
            return 24
    @property
    def h(self):
        return {5:5, 6:10, 7:15, 8:20, 9:25, 10:5, 11:10, 12:15, 13:20, 14:25}[self.value]
