import os
import io
from os import cpu_count
import pickle
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
from .lms import LMS_Priv
from .utils import FAILURE
from hashlib import sha384

version = '0.1'

def kdf(salt, password):
    return PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=390000).derive(password)


class LMS_Wrapper_Priv(LMS_Priv):
    """
    Class derived from LMS_Priv.

    It is used to generate the private key and derive the public key of a LMS signature system.
    The private key is signed and stored in an encrypted file.

    Args:
        lmstypecodes: List of LMS_ALGORITHM_TYPE 
        otstypecode: LMOTS_ALGORITHM_TYPE
        filename (str): holds the name of the file to store the key
        password (bytes): password to sign and encrypt the file
        frequence (int): frequnce at which the key is stored to a file
    """
    FILEHEADER = b'LMSWrapper_Priv_v\x00' + version.encode('utf-8')
    def __init__(self, lmstypecodes, otstypecode, filename, password, frequence = None, num_cores = None):
        if num_cores is None:
            num_cores = cpu_count()
        super().__init__(lmstypecodes, otstypecode, num_cores) 
        self.filename = filename
        if frequence is None:
            frequence = 1
        self.frequence = frequence
        self.sign_count = 0
        self.salt = os.urandom(16)
        self.key = kdf(self.salt, password)
  
    def sign(self, message):
        """
        Signs the message with the private key associated with the class.

        The key is automatically stored to disk after frequence signatures.

        Args:
            message (bytes, BufferedReader): Message to be signed
        
        Raises:
            FAILURE: If a signature has already been computed, or for other technical reason
        
        Returns:
            bytes: The signature to `message`.
        """
        # sha384 of the message.
        message_digest = sha384(message).digest()

        signature = super().sign(message_digest)
        self.sign_count += 1

        # check for the below comments later
        if self.sign_count % self.frequence == 0:
            self.save()
        
        return signature

    def save(self):
        """
        This method is to save the key.
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
                fout.write(LMS_Wrapper_Priv.FILEHEADER)
                fout.write(self.salt)
                fout.write(nonce)
                fout.write(aesgcm.encrypt(nonce, data, LMS_Wrapper_Priv.FILEHEADER))
        except IOError:
            raise FAILURE("File %s cannot be saved." % self.filename)
        
        try:
            os.remove(self.filename + '.bak')
        except OSError:
            pass

    def from_file(self, filename, password):
        """
        A key, LMS_Priv is loaded from a password-protected file.

        Frequence signatures are skipped to ensure that no private key is used more than once.
        
        Raises:
            FAILURE: if the key cannot be loaded
        
        Returns:
            LMS_Priv
        """
        try:
            with open(filename, 'rb') as fin:
                fh = fin.read(len(LMS_Wrapper_Priv.FILEHEADER))
                if fh != LMS_Wrapper_Priv.FILEHEADER:
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
                sk = pickle.load(io.BytesIO(data)) # sk object returns lms_wrapper.LMS_Wrapper_Priv type
                if not type(sk) is LMS_Wrapper_Priv:
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

    def verify(self, message, signature, public_key):
        """
        Signature is verified using public key.

        Args:
            message
            signature
            public_key
        
        Returns:
            True if signature is correct else False
        """
        # sha384 of the message
        message_digest = sha384(message).digest()

        try:
            public_key.verify(message_digest, signature)
            return True
        except:
            return False
