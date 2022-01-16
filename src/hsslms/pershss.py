#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sat Jan  1 20:00:55 2022

@author: mvr
"""
import os
import pickle
from .restricted_unpickler import restricted_loads
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
from .hss import HSS_Priv
from .utils import FAILURE
from . import __version__


def kdf(salt, password):
    return PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=390000).derive(password)


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
    FILEHEADER = b'PersHSS_Priv_v\x00' + __version__.encode('utf-8')
    def __init__(self, lmstypecodes, otstypecode, filename, password, frequence, num_cores):
        """
        Parameters
        ----------
        lmstypecodes : List of LMS_ALGORITHM_TYPE
        otstypecode  : LMOTS_ALGORITHM_TYPE
        filename     : str, holds the name of the file to store the key
        password     : bstr, password to sign and encrypt the file
        frequence    : frequnce at which the key is stored to a file
        """
        super().__init__(lmstypecodes, otstypecode, num_cores)
        self.filename = filename
        self.password = password
        self.frequence = frequence
        self.sign_count = 0
        self.salt = os.urandom(16);
        self.key = kdf(self.salt, password)
        
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
        data = pickle.dumps(self)
        aesgcm = AESGCM(self.key)
        nonce = os.urandom(12)
        try:
            with open(self.filename, 'wb') as fout:
                fout.write(PersHSS_Priv.FILEHEADER)
                fout.write(self.salt)
                fout.write(nonce)
                fout.write(aesgcm.encrypt(nonce, data, PersHSS_Priv.FILEHEADER))
        except IOError:
            raise FAILURE("File %s cannot be saved." % self.filename)
        try:
            os.remove(self.filename + '.bak')
        except OSError:
            pass
            
        
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
        try:
            with open(filename, 'rb') as fin:
                fh = fin.read(len(PersHSS_Priv.FILEHEADER))
                if fh != PersHSS_Priv.FILEHEADER:
                    raise FAILURE("Invalid file type.")
                salt = fin.read(16)
                if len(salt) < 16:
                    raise FAILURE("Invalid file.")
                key = kdf(salt, password)
                aesgcm = AESGCM(key)
                nonce = fin.read(12)
                if len(nonce) < 12:
                    raise FAILURE("Invalid file.")
                data = aesgcm.decrypt(nonce, fin.read(), fh)
                sk = restricted_loads(data)
                if not type(sk) is PersHSS_Priv:
                    raise FAILURE("Wrong Object Type.")
        except InvalidTag:
            raise FAILURE("Wrong password.")
        except IOError:
            raise FAILURE("File %s cannot be read." % filename)
        except pickle.PickleError as e:
            print(e)
            raise FAILURE("Cannot load private key.")
        # skip next signatures
        for _ in range(sk.frequence-1):
            sk.sign(b'')
        return sk



