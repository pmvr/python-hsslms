#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sat Jan  1 11:49:13 2022

@author: mvr
"""
from os import urandom
from .utils import LMOTS_ALGORITHM_TYPE
from .utils import INVALID, FAILURE
from .utils import D_MESG, D_PBLC
from .utils import coef, cksm, u16str, u8str, u32str


class LM_OTS_Pub:
    """
    A class used to hold the public key of Leighton-Micali One-Time-Signatures (LMOTS)

    Methods
    -------
    verify(message, signature)
        tries to verify the signature of a message with the public key associated with the class
    """
    
    def __init__(self, pubkey):
        """
        Parameters
        ----------
        pubkey : bstr
            typecode || I || q || K
        """
        try:
            self.pubtype = LMOTS_ALGORITHM_TYPE(int.from_bytes(pubkey[:4], 'big'))
        except ValueError:
            raise INVALID
        n = self.pubtype.n
        if len(pubkey) != 24+n:
            raise INVALID
        self.I = pubkey[4:4+16]  # 16-byte string
        self.q = pubkey[20:20+4]
        self.K = pubkey[24:]
        self.pubkey = pubkey
        
    def algo4b(self, message, signature):
        if len(signature) < 4:
            raise INVALID
        sigtype = LMOTS_ALGORITHM_TYPE(int.from_bytes(signature[:4], 'big'))
        if self.pubtype != sigtype:
            raise INVALID
        H, n, w, p, ls = sigtype.H, sigtype.n, sigtype.w, sigtype.p, sigtype.ls
        if len(signature) != 4 + n * (p+1):
            raise INVALID
        C = signature[4:4+n]
        y = [signature[4+n+i*n : 4+n+(i+1)*n] for i in range(p)]
        Q = H(self.I + self.q + D_MESG + C + message).digest()
        z = []
        for i in range(p):
            a = coef(Q + cksm(Q, w, n, ls), i, w)
            tmp = y[i]
            for j in range(a, 2**w - 1):
                tmp = H(self.I + self.q + u16str(i) + u8str(j) + tmp).digest()
            z.append(tmp)
        return H(self.I + self.q + D_PBLC + b''.join(z)).digest()  # Kc
        
    
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
        Kc = self.algo4b(message, signature)
        if Kc != self.K:
            raise INVALID
                
    def __repr__(self):
        return str(self.pubkey)

        
class LM_OTS_Priv:
    """
    A class used to generate the private key and derive the public key of Leighton-Micali One-Time-Signatures (LMOTS)

    Methods
    -------
    sign(message)
        signs the message with the private key associated with the class
    gen_pub
        computes the public key, i.e. an instance of LM_OTS_Pub
    """
    
    def __init__(self, typecode, I, q):
        """
        Parameters
        ----------
        typecode : LMOTS_ALGORITHM_TYPE
        I        : bstr (16 random bytes)
        q        : int
        """
        self.I = I
        self.q = q
        self.H, self.n, self.w, self.p, self.ls = typecode.H, typecode.n, typecode.w, typecode.p, typecode.ls
        self.typecode = u32str(typecode.value)
        self.x = [urandom(self.n) for _ in range(self.p)]
        self.used = False

    def sign(self, message):
        """
        Signs the message with the private key associated with the class.
        
        Parameters
        ----------
        message : bstr
        
        Raises:
        FAILURE
            if a signature has already been computed
        
        Returns
        ------
        signature
        """
        if self.used == True:
            raise FAILURE
        C = urandom(self.n)
        y = []
        Q = self.H(self.I + u32str(self.q) + D_MESG + C + message).digest()
        for i in range(self.p):
            a = coef(Q + cksm(Q, self.w, self.n, self.ls), i, self.w)
            tmp = self.x[i]
            for j in range(a):
                tmp = self.H(self.I + u32str(self.q) + u16str(i) + u8str(j) + tmp).digest()
            y.append(tmp)
        self.used = True
        return self.typecode + C + b''.join(y)

    def gen_pub(self):
        """
        Computes the public key associated with the private key in this class.
        
        Returns
        ------
        an instance of LM_OTS_Pub
        """
        u32str_q = u32str(self.q)
        K = self.H(self.I + u32str_q + D_PBLC)
        u8str_j = [u8str(j) for j in range(2**self.w - 1)]
        for i, tmp in zip([u16str(i) for i in range(self.p)], self.x):
            for j in u8str_j:
                tmp = self.H(self.I + u32str_q + i + j + tmp).digest()
            K.update(tmp)
        return LM_OTS_Pub(self.typecode + self.I + u32str_q  + K.digest())

    def __repr__(self):
        return str(self.typecode + self.I + u32str(self.q) + b''.join(self.x))
