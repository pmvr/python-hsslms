# -*- coding: utf-8 -*-
"""LM-OTS One-Time Signatures

For reference see RFC 8554, section 4.
"""
import io
from secrets import token_bytes
from .utils import LMOTS_ALGORITHM_TYPE
from .utils import INVALID, FAILURE
from .utils import D_MESG, D_PBLC
from .utils import coef, cksm, u16str, u8str, u32str


class LM_OTS_Pub:
    """A class used to hold the public key of LM-OTS One-Time Signatures (LMOTS)
    
    For a reference see RFC 8554, section 4.
    """
    
    def __init__(self, pubkey):
        """Constructor for LMOTS Public Keys

        Args:
            pubkey (bytes): typecode || I || q || K
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
        
    def _algo4b(self, message, signature):
        if len(signature) < 4:
            raise INVALID
        sigtype = LMOTS_ALGORITHM_TYPE(int.from_bytes(signature[:4], 'big'))
        if self.pubtype != sigtype:
            raise INVALID
        H, n, w, p, ls = sigtype.H, sigtype.n, sigtype.w, sigtype.p, sigtype.ls
        if len(signature) != 4 + n * (p+1):
            raise INVALID
        C = signature[4:4+n]
        if type(message) is bytes:
            Q = H(self.I + self.q + D_MESG + C + message)
        elif type(message) is io.BufferedReader:
            Q = H(self.I + self.q + D_MESG + C )
            try:
                while True:
                    buffer = message.read(1024**2)
                    Q.update(buffer)
                    if len(buffer) < 1024**2:
                        break
                message.close()
            except IOError:
                raise FAILURE("Error. Cannot read message.")
        else:
            raise FAILURE("Invalid message type.")
        Q = Q.digest()
        Qa = Q + cksm(Q, w, n, ls)
        Kc = H(self.I + self.q + D_PBLC)
        for i in range(p):
            a = coef(Qa, i, w)
            tmp = signature[4+n+i*n : 4+n+(i+1)*n]  # y[i]
            for j in range(a, 2**w - 1):
                tmp = H(self.I + self.q + u16str(i) + u8str(j) + tmp).digest()
            Kc.update(tmp)  # z
        return Kc.digest()  # Kc
        
    
    def verify(self, message, signature):
        """Signature Verification of LMOTS
        
        Tries to verify the signature of a message with the public key associated
        with the class.
        
        Args:
            message (bytes, BufferedReader): Message to be verified with `signature`
            signature (bytes): Signature belonging to the `message`
        
        Raises:
            INVALID: If signature is invalid.
        """
        Kc = self._algo4b(message, signature)
        if Kc != self.K:
            raise INVALID
                
    def __repr__(self):
        return str(self.pubkey)

        
class LM_OTS_Priv:
    """A class used to hold the private key of LM-OTS One-Time Signatures (LMOTS)
    
    For a reference see RFC 8554, section 4.
    
    This class can be used to generate the belonging public key `LM_OTS_Pub`.
    """
    
    def __init__(self, typecode, I, q):
        """Constructor for LMOTS Private Keys
        
        Args:
            typecode (LMOTS_ALGORITHM_TYPE): Enumeration of Leighton-Micali One-Time-Signatures (LMOTS) algorithm types
            I (bytes): 16 random bytes
            q (int): 32-bit number / no.
        """
        self.I = I
        self.q = q
        self.H, self.n, self.w, self.p, self.ls = typecode.H, typecode.n, typecode.w, typecode.p, typecode.ls
        self.typecode = u32str(typecode.value)
        self.x = [token_bytes(self.n) for _ in range(self.p)]
        self.used = False

    def sign(self, message):
        """Signature Generation of LMOTS
        
        Signs a message with the private key associated with the class.
        
        Args:
            message (bytes, BufferedReader): Message to be signed
        
        Raises:
            FAILURE: If a signature has already been computed, or for other
                technical reason
        
        Returns:
            bytes: The signature to `message`.
        """
        if self.used == True:
            raise FAILURE("Private key has already been used for signing.")
        C = token_bytes(self.n)
        signature = self.typecode + C;
        if type(message) is bytes:
            Q = self.H(self.I + u32str(self.q) + D_MESG + C + message)
        elif type(message) is io.BufferedReader:
            Q = self.H(self.I + u32str(self.q) + D_MESG + C)
            try:
                while True:
                    buffer = message.read(1024**2)
                    Q.update(buffer)
                    if len(buffer) < 1024**2:
                        break
                message.close()
            except IOError:
                raise FAILURE("Error. Cannot read message.")
        else:
            raise FAILURE("Invalid message type.")
        Q = Q.digest()
        Qa = Q + cksm(Q, self.w, self.n, self.ls)
        for i in range(self.p):
            a = coef(Qa, i, self.w)
            tmp = self.x[i]
            for j in range(a):
                tmp = self.H(self.I + u32str(self.q) + u16str(i) + u8str(j) + tmp).digest()
            signature += tmp  # y
        self.used = True
        return signature

    def gen_pub(self):
        """Computes the public key associated with the private key in this class.
        
        Returns:
            LM_OTS_Pub: The public key belonging to this private key.
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
