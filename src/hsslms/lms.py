#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sat Jan  1 11:53:08 2022

@author: mvr
"""
from os import urandom, cpu_count
from multiprocessing import Pool
from .utils import LMOTS_ALGORITHM_TYPE, LMS_ALGORITHM_TYPE
from .utils import INVALID, FAILURE
from .utils import D_LEAF, D_INTR
from .utils import u32str, strTou32
from .lmots import LM_OTS_Priv, LM_OTS_Pub


class LMS_Pub:
    """
    A class used to hold the public key of Leighton-Micali Signatures (LMS)

    Methods
    -------
    verify(message, signature)
        tries to verify the signature of a message with the public key associated with the class
    """
    def __init__(self, pubkey):
        if len(pubkey) < 8:
            raise INVALID
        try:
            self.pubtype = LMS_ALGORITHM_TYPE(strTou32(pubkey[:4]))
        except ValueError:
            raise INVALID
        self.H, self.m, self.h = self.pubtype.H, self.pubtype.m, self.pubtype.h
        if len(pubkey) != 24+self.m:
            raise INVALID
        self.otspubtype = LMOTS_ALGORITHM_TYPE(int.from_bytes(pubkey[4:4+4], 'big'))
        self.I = pubkey[8:8+16]
        self.T1 = pubkey[24:]
        self.pubkey = pubkey
        
    def len_pubkey(pubkey):
        return 24 + LMS_ALGORITHM_TYPE(strTou32(pubkey[:4])).m
        
    def algo6b(self, message, signature):
        if len(signature) < 8:
            raise INVALID
        q = strTou32(signature[:4])
        otssigtype = LMOTS_ALGORITHM_TYPE(strTou32(signature[4:4+4]))
        if self.otspubtype != otssigtype:
            raise INVALID
        n, p = otssigtype.n, otssigtype.p
        if len(signature) < 12 + n*(p+1):
            raise INVALID
        lmots_signature = signature[4:8 + n*(p+1)]
        sigtype = LMS_ALGORITHM_TYPE(strTou32(signature[8+n*(p+1):12+n*(p+1)]))
        if self.pubtype != sigtype:
            raise INVALID
        if q >= 2**self.h or len(signature) != 12+n*(p+1)+self.m*self.h:
            raise INVALID
        path = [signature[12+n*(p+1)+i*self.m:12+n*(p+1)+(i+1)*self.m] for i in range(self.h)]
        OTS_PUB = LM_OTS_Pub(lmots_signature[:4] + self.I + u32str(q)  + b'\x00'*n)
        Kc = OTS_PUB.algo4b(message, lmots_signature)
        node_num = 2**self.h + q
        tmp = self.H(self.I + u32str(node_num) + D_LEAF + Kc).digest()
        i = 0
        while node_num > 1:
            if node_num % 2 == 1:
                tmp = self.H(self.I + u32str(node_num//2) + D_INTR + path[i] + tmp).digest()
            else:
                tmp = self.H(self.I + u32str(node_num//2) + D_INTR + tmp + path[i]).digest()
            node_num >>= 1
            i += 1
        return tmp  # Tc
        
    def verify(self, message, signature):
        """
        Tries to verify the signature of a message with the public key associated with the class.
        
        Parameters
        ----------
        message : bstr
        signature : bstr
        
        Raises
        ------
        INVALID
            If signature is invalid.
        """
        Tc = self.algo6b(message, signature)
        if Tc != self.T1:
            raise INVALID
            
    def len_signature(signature):
        otssigtype = LMOTS_ALGORITHM_TYPE(strTou32(signature[4:4+4]))
        n, p = otssigtype.n, otssigtype.p
        sigtype = LMS_ALGORITHM_TYPE(strTou32(signature[8+n*(p+1):12+n*(p+1)]))
        return 12 + n*(p+1) + sigtype.m * sigtype.h
                
            
    def get_pubkey(self):
        return self.pubkey
        

class LMS_Priv:
    """
    A class used to generate the private key and derive the public key of Leighton-Micali Signatures (LMS)

    Methods
    -------
    sign(message)
        signs the message with the private key associated with the class
    gen_pub
        computes the public key, i.e. an instance of LM_OTS_Pub
    """
    def calc_K(x):
        return x.gen_pub().K
    def calc_hash(H, *l):
        return H(b''.join(l)).digest()
    
    def __init__(self, typecode, otstypecode, num_cores=None):
        """
        Parameters
        ----------
        typecode    : LMS_ALGORITHM_TYPE
        otstypecode : LMOTS_ALGORITHM_TYPE
        num_cores   : int | None (default)
            the number of CPU cores used for key generation, None=all cores
        """
        if num_cores is None:
            num_cores = cpu_count()
        self.typecode = typecode
        self.otstypecode = otstypecode
        self.H, self.m, self.h = self.typecode.H, self.typecode.m, self.typecode.h
        self.I = urandom(16)
        self.OTS_PRIV = []
        for q in range(2**self.h):
            self.OTS_PRIV.append(LM_OTS_Priv(self.otstypecode, self.I, q))
        self.q = 0
        self.T = [None]*(2**(self.h+1))
        with Pool(num_cores) as p:
            OTS_PUB_HASH = p.map(LMS_Priv.calc_K, self.OTS_PRIV)
            self.T[2**self.h : 2**(self.h+1)] = p.starmap(LMS_Priv.calc_hash, ((self.H, self.I, u32str(r), D_LEAF, OTS_PUB_HASH[r-2**self.h]) for r in range(2**self.h, 2**(self.h+1))))
            for i in range(self.h-1, -1, -1):
                self.T[2**i : 2**(i+1)] = p.starmap(LMS_Priv.calc_hash, ((self.H, self.I, u32str(r), D_INTR, self.T[2*r], self.T[2*r+1]) for r in range(2**i, 2**(i+1))))
        
    def sign(self, message):
        """
        Signs the message with the private key associated with the class.
        
        Parameters
        ----------
        message : bstr
        
        Raises:
        FAILURE
            if private keys are exhausted
        
        Returns
        ------
        signature
        """
        if self.q >= 2**self.h:
            raise FAILURE
        lmots_signature = self.OTS_PRIV[self.q].sign(message)
        path = []
        r = 2**self.h + self.q
        for i in range(self.h):
            path.append(self.T[r ^ 1])
            r >>= 1
        signature = u32str(self.q) + lmots_signature + u32str(self.typecode.value) + b''.join(path)
        self.q += 1
        return signature
        
    def gen_pub(self):
        """
        Computes the public key associated with the private key in this class.
        
        Returns
        ------
        an instance of LMS_Pub
        """
        return LMS_Pub(u32str(self.typecode.value) + u32str(self.otstypecode.value) + self.I + self.T[1])
    
    def get_avail_signatures(self):
        return len(self.OTS_PRIV) - self.q
    
