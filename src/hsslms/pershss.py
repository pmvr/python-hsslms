#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sat Jan  1 20:00:55 2022

@author: mvr
"""
import os
import pickle
from hashlib import pbkdf2_hmac
from hashlib import sha256
import hmac
import subprocess
from .hss import HSS_Priv
from .utils import FAILURE


class PersHSS_Priv(HSS_Priv):
    """
    A class derived from HSS_Priv. It is used to generate the private key and
    derive the public key of a Hierarchical Signature System (HSS)
    The private key is signed and stored in an encrypted file.

    Methods
    -------
    sign(message)
        signs the message with the private key associated with the class
    gen_pub
        computes the public key, i.e. an instance of HSS_Pub
    save
        saves the private key to a file.
    from_file
        loads a private key, i.e. HSS_Priv, from a file
    """
    def __init__(self, lmstypecodes, otstypecode, filename, password, frequence):
        """
        Parameters
        ----------
        lmstypecodes : List of LMS_ALGORITHM_TYPE
        otstypecode  : LMOTS_ALGORITHM_TYPE
        filename     : str, holds the name of the file to store the key
        password     : bstr, password to sign and encrypt the file
        frequence    : frequnce at which the key is stored to a file
        """
        super().__init__(lmstypecodes, otstypecode)
        self.filename = filename
        self.password = password
        self.frequence = frequence
        self.sign_count = 0
        
    def sign(self, message):
        """
        Signs the message with the private key associated with the class.
        The key is automatically stored to disk after frequnce signatures.        
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
        signature = super().sign(message)
        self.sign_count += 1
        if self.sign_count % self.frequence == 0:
            self.save()
        return signature
        
    def save(self):
        """
        The key is saved.
        """
        try:
            os.rename(self.filename, self.filename + '.bak')
        except FileNotFoundError:
            pass
        password = self.password
        self.password = b''
        salt = os.urandom(16)
        dkey = pbkdf2_hmac('sha256', password, salt, 100000)
        data = pickle.dumps(self)
        mac = hmac.new(dkey, msg=data, digestmod=sha256).digest()
        subprocess.run(["openssl", "enc", "-aes-256-cbc", "-pbkdf2", "-k", password.decode('utf8'), "-out", self.filename], input=salt+mac+data)

    def from_file(filename, password):
        """
        A key, HSS_Priv, is loaded from a password-protected file.
        Frequnce signatures are skipped to ensure that no private key is used
        more than once.
        
        Parameters
        ----------
        filename : str, name of the file
        password : bstr
        
        Raises:
        FAILURE
            if the key cannot be loaded
        
        Returns
        ------
        HSS_Priv
        """
        cp = subprocess.run(["openssl", "enc", "-aes-256-cbc", "-d", "-pbkdf2", "-k", password.decode('utf8'), "-in", filename], capture_output=True)
        if cp.returncode != 0:
            raise FAILURE('Error decrypting file.')
        salt = cp.stdout[:16]
        mac = cp.stdout[16:16+32]
        data = cp.stdout[16+32:]
        dkey = pbkdf2_hmac('sha256', password, salt, 100000)
        if hmac.compare_digest(mac, hmac.new(dkey, msg=data, digestmod=sha256).digest()) == False:
            raise FAILURE('HMAC verification failed.')
        sk = pickle.loads(data)
        sk.password = password
        # skip next signatures
        for _ in range(sk.frequence):
            sk.sign(b'')
        return sk
