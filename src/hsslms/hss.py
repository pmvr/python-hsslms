#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sat Jan  1 11:56:44 2022

@author: mvr
"""
from .lms import LMS_Priv, LMS_Pub
from .utils import INVALID, FAILURE
from .utils import u32str, strTou32


class HSS_Pub:
    """
    A class used to hold the public key of a Hierarchical Signature System (HSS)

    Methods
    -------
    verify(message, signature)
        tries to verify the signature of a message with the public key associated with the class
    """
    def __init__(self, pubkey):
        self.L = strTou32(pubkey[:4])
        self.pub = LMS_Pub(pubkey[4:])
        
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
        Nspk = strTou32(signature[:4])
        if Nspk+1 != self.L:
            raise INVALID
        signature = signature[4:]
        siglist = []
        publist = []
        for i in range(Nspk):
            l = LMS_Pub.len_signature(signature)
            siglist.append(signature[:l])
            signature = signature[l:]
            l = LMS_Pub.len_pubkey(signature)
            publist.append(signature[:l])
            signature = signature[l:]
        key = self.pub
        for i in range(Nspk):
            key.verify(publist[i], siglist[i])
            key = LMS_Pub(publist[i])
        key.verify(message, signature)


class HSS_Priv:
    """
    A class used to generate the private key and derive the public key of a Hierarchical Signature System (HSS)

    Methods
    -------
    sign(message)
        signs the message with the private key associated with the class
    gen_pub
        computes the public key, i.e. an instance of HSS_Pub
    """
    
    def __init__(self, lmstypecodes, otstypecode, num_cores=None):
        """
        Parameters
        ----------
        lmstypecodes : List of LMS_ALGORITHM_TYPE
        otstypecode  : LMOTS_ALGORITHM_TYPE
        num_cores   : int | None (default)
            the number of CPU cores used for key generation, None=all cores
       """
        self.lmstypecodes = lmstypecodes
        self.otstypecode = otstypecode
        self.L = len(lmstypecodes)
        self.priv = [LMS_Priv(self.lmstypecodes[0], self.otstypecode, num_cores)]
        self.pub = [self.priv[0].gen_pub()]
        self.sig = []
        for i in range(1, self.L):
            self.priv.append(LMS_Priv(self.lmstypecodes[i], self.otstypecode, num_cores))
            self.pub.append(self.priv[-1].gen_pub())
            self.sig.append(self.priv[-2].sign(self.pub[-1].get_pubkey()))
        
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
        d = self.L
        while self.priv[d-1].get_avail_signatures() == 0:
            d -= 1
            if d == 0:
                raise FAILURE
        for i in range(d, self.L):
            self.priv[i] = LMS_Priv(self.lmstypecodes[i], self.otstypecode)
            self.pub[i] = self.priv[i].gen_pub()
            self.sig[i-1] = self.priv[i-1].sign(self.pub[i].get_pubkey())
        sig = self.priv[-1].sign(message)
        signed_pub_key = []
        for i in range(self.L-1):
            signed_pub_key.append(self.sig[i] + self.pub[i+1].get_pubkey())
        return u32str(self.L-1) + b''.join(signed_pub_key) + sig

    def gen_pub(self):
        """
        Computes the public key associated with the private key in this class.
        
        Returns
        ------
        an instance of HSS_Pub
        """
        return HSS_Pub(u32str(self.L) + self.pub[0].get_pubkey())
