# -*- coding: utf-8 -*-
"""Leighton-Micali Hash-Based Signatures

This modulue provides an implementation of Leighton-Micali Hash-Based Signatures
in Python according to RFC 8554, https://www.rfc-editor.org/rfc/rfc8554.html.

  * For LM-OTS One-Time Signatures the classes LM_OTS_Priv and LM_OTS_Pub can be used.
  * For Leighton-Micali Signatures the classes LMS_Priv and LMS_Pub can be used.
  * For Hierarchical Signatures the classes HSS_Priv and HSS_Pub can be used.
  
There is also a command line script available ``hsslms`` which can be used for Hierarchical Signatures.
  
Example:
    LM-OTS One-Time Signatures::
        from os import urandom
        from hsslms import LM_OTS_Priv
        
        # generate a one-time private key
        sk = LM_OTS_Priv(LMOTS_ALGORITHM_TYPE.LMOTS_SHA256_N32_W2, urandom(16), 0)
        # sign a message with the private key
        signature = sk.sign(b'abc')
        # compute the related public key
        vk = sk.gen_pub()
        # verify the signature, if invalid an exception will be raised
        vk.verify(b'abc', signature)
        
    Leighton-Micali Signatures::
        from os import urandom
        from hsslms import LMS_Priv
        
        # generate a private key
        sk = LMS_Priv(LMS_ALGORITHM_TYPE.LMS_SHA256_M32_H10, LMOTS_ALGORITHM_TYPE.LMOTS_SHA256_N32_W8)
        # sign a message with the private key, in total 2^10 signatures are available
        signature = sk.sign(b'abc')
        # compute the related public key
        vk = sk.gen_pub()
        # verify the signature, if invalid an exception will be raised
        vk.verify(b'abc', signature)
        
    Hierarchical Signatures::
        from os import urandom
        from hsslms import HSS_Priv
        
        # generate a private key
        sk = HSS_Priv([LMS_ALGORITHM_TYPE.LMS_SHA256_M32_H10]*2, LMOTS_ALGORITHM_TYPE.LMOTS_SHA256_N32_W1)
        # sign a message with the private key, in total 2^20 signatures are available
        signature = sk.sign(b'abc')
        # compute the related public key
        vk = sk.gen_pub()
        # verify the signature, if invalid an exception will be raised
        vk.verify(b'abc', signature)
"""

__all__ = ['INVALID', 'FAILURE', 'LMOTS_ALGORITHM_TYPE', 'LMS_ALGORITHM_TYPE', 'LM_OTS_Pub', 'LM_OTS_Priv', 'LMS_Pub', 'LMS_Priv', 'HSS_Pub', 'HSS_Priv', 'PersHSS_Priv']
__version__ = '0.1.0'

from .utils import INVALID, FAILURE
from .utils import LMOTS_ALGORITHM_TYPE, LMS_ALGORITHM_TYPE
from .lmots import LM_OTS_Priv, LM_OTS_Pub
from .lms import LMS_Priv, LMS_Pub
from .hss import HSS_Pub, HSS_Priv
from .pershss import PersHSS_Priv
