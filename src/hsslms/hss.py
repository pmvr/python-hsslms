# -*- coding: utf-8 -*-
"""Hierarchical Signatures

For reference see RFC 8554, section 6.
"""
from .lms import LMS_Priv, LMS_Pub
from .utils import INVALID, FAILURE
from .utils import u32str, strTou32


class HSS_Pub:
    """A class used to hold the public key of Hierarchical Signatures (HSS)
    
    This hierarchical scheme uses LMS as a component.
    
    For a reference see RFC 8554, section 6.
    """
    def __init__(self, pubkey):
        """Constructor for HSS Public Keys

        Args:
            pubkey (bytes): u32str(L) || LMS Public Key[0]
            
        Raises:
            INVALID: If the public is invalid.
        """
        if len(pubkey) < 4:
            raise INVALID
        self.L = strTou32(pubkey[:4])
        self.pub = LMS_Pub(pubkey[4:])
        
    def verify(self, message, signature):
        """Signature Verification of HSS

        Tries to verify the signature of a message with the public key associated
        with the class.
        
        Args:
            message (bytes, BufferedReader): Message to be verified with `signature`
            signature (bytes): Signature belonging to the `message`
        
        Raises:
            INVALID: If signature is invalid.
        """
        Nspk = strTou32(signature[:4])
        if Nspk+1 != self.L:
            raise INVALID
        signature = signature[4:]
        key = self.pub
        for i in range(Nspk):
            l = LMS_Pub._len_signature(signature)
            lms_sig = signature[:l]
            signature = signature[l:]
            l = LMS_Pub._len_pubkey(signature)
            lms_pub = signature[:l]
            key.verify(lms_pub, lms_sig)
            signature = signature[l:]
            key = LMS_Pub(lms_pub)
        key.verify(message, signature)
        
    def get_pubkey(self):
        return u32str(self.L) + self.pub.get_pubkey()
    
    def info(self):
        return f"Height L: {self.L}\n" + self.pub.info()
        


class HSS_Priv:
    """A class used to hold the private key of Hierarchical Signatures (HSS)
    
    For a reference see RFC 8554, section 6.
    
    This class can be used to generate the belonging public key `HSS_Pub`.
    """
    
    def __init__(self, lmstypecodes, otstypecode, num_cores=None):
        """Constructor for HSS Private Keys
        
        Args:
            lmstypecodes (:obj:`list` of :obj:`LMS_ALGORITHM_TYPE`): List of enumeration of Leighton-Micali Signatures (LMS) algorithm types
            otstypecode (LMOTS_ALGORITHM_TYPE): Enumeration of Leighton-Micali One-Time-Signatures (LMOTS) algorithm types
            num_cores (int, None, optional): the number of CPU cores used for key generation, None=all cores
        """
        self.lmstypecodes = lmstypecodes
        self.otstypecode = otstypecode
        self.L = len(lmstypecodes)
        self.priv = [LMS_Priv(self.lmstypecodes[0], self.otstypecode, num_cores)]
        self.avail_signatures = self.priv[0].get_avail_signatures()
        self.pub = [self.priv[0].gen_pub()]
        self.sig = []
        for i in range(1, self.L):
            self.priv.append(LMS_Priv(self.lmstypecodes[i], self.otstypecode, num_cores))
            self.avail_signatures *= self.priv[-1].get_avail_signatures()
            self.pub.append(self.priv[-1].gen_pub())
            self.sig.append(self.priv[-2].sign(self.pub[-1].get_pubkey()))
        
    def sign(self, message):
        """Signature Generation of HSS
        
        Signs a message with the private key associated with the class.
        
        Args:
            message (bytes, BufferedReader): Message to be signed
        
        Raises:
            FAILURE: If a signature has already been computed, or for other
                technical reason
        
        Returns:
            bytes: The signature to `message`.
        """
        d = self.L
        while self.priv[d-1].get_avail_signatures() == 0:
            d -= 1
            if d == 0:
                raise FAILURE("Private keys exhausted.")
        for i in range(d, self.L):
            self.priv[i] = LMS_Priv(self.lmstypecodes[i], self.otstypecode)
            self.pub[i] = self.priv[i].gen_pub()
            self.sig[i-1] = self.priv[i-1].sign(self.pub[i].get_pubkey())
        signature = u32str(self.L-1)
        for i in range(self.L-1):
            signature += self.sig[i] + self.pub[i+1].get_pubkey()  # signed_pub_key
        self.avail_signatures -= 1
        return signature + self.priv[-1].sign(message)

    def gen_pub(self):
        """Computes the public key associated with the private key in this class.
        
        Returns:
            HSS_Pub: The public key belonging to this private key.
        """
        return HSS_Pub(u32str(self.L) + self.pub[0].get_pubkey())
    
    def get_avail_signatures(self):

        """Computes the numbers of availalbe signatures.
        
        Every invokation of the 'sign'-Method reduces this number by one.
        
        Returns:
            int: The remaining number of signatures that can be generated.
        """
        return self.avail_signatures
    
    def info(self):
        return f"""\
lmotstype = {self.otstypecode.name}
lmstypes = {[t.name for t in self.lmstypecodes]}
available signatures = {self.get_avail_signatures()}
"""
