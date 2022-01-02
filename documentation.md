Module hsslms
=============
Created on Thu Dec 23 09:14:46 2021

@author: mvr

https://www.rfc-editor.org/rfc/rfc8554.html

Sub-modules
-----------
* hsslms.hss
* hsslms.lmots
* hsslms.lms
* hsslms.pershss
* hsslms.test
* hsslms.utils

Classes
-------

`FAILURE(*args, **kwargs)`
:   Exception if no private key is left to sign.

    ### Ancestors (in MRO)

    * builtins.Exception
    * builtins.BaseException

`HSS_Priv(lmstypecodes, otstypecode, num_cores=None)`
:   A class used to generate the private key and derive the public key of a Hierarchical Signature System (HSS)
    
    Methods
    -------
    sign(message)
        signs the message with the private key associated with the class
    gen_pub
        computes the public key, i.e. an instance of HSS_Pub
    
    Parameters
    ----------
    lmstypecodes : List of LMS_ALGORITHM_TYPE
    otstypecode  : LMOTS_ALGORITHM_TYPE
    num_cores   : int | None (default)
        the number of CPU cores used for key generation, None=all cores

    ### Descendants

    * hsslms.pershss.PersHSS_Priv

    ### Methods

    `gen_pub(self)`
    :   Computes the public key associated with the private key in this class.
        
        Returns
        ------
        an instance of HSS_Pub

    `sign(self, message)`
    :   Signs the message with the private key associated with the class.
        
        Parameters
        ----------
        message : bstr
        
        Raises:
        FAILURE
            if private keys are exhausted
        
        Returns
        ------
        signature

`HSS_Pub(pubkey)`
:   A class used to hold the public key of a Hierarchical Signature System (HSS)
    
    Methods
    -------
    verify(message, signature)
        tries to verify the signature of a message with the public key associated with the class

    ### Methods

    `verify(self, message, signature)`
    :   Tries to verify the signature of a message with the public key associated with the class.
        
        Parameters
        ----------
        message : bstr
        signature : bstr
        
        Raises
        ------
        INVALID
            If signature is invalid.

`INVALID(*args, **kwargs)`
:   Exception for an invalid signature.

    ### Ancestors (in MRO)

    * builtins.Exception
    * builtins.BaseException

`LMOTS_ALGORITHM_TYPE(value, names=None, *, module=None, qualname=None, type=None, start=1)`
:   Enumeration of Leighton-Micali One-Time-Signatures (LMOTS) algorithm types, see rfc8554.
    
    Attributes
    ----------
    H : Hashfunction
    n : Outputlength of the hashfunction
    w : number of simultanious signes bits
    p : internal dependent parameter
    ls : internal dependent parameter

    ### Ancestors (in MRO)

    * enum.Enum

    ### Class variables

    `LMOTS_SHA256_N32_W1`
    :

    `LMOTS_SHA256_N32_W2`
    :

    `LMOTS_SHA256_N32_W4`
    :

    `LMOTS_SHA256_N32_W8`
    :

    ### Instance variables

    `H`
    :

    `ls`
    :

    `n`
    :

    `p`
    :

    `w`
    :

`LMS_ALGORITHM_TYPE(value, names=None, *, module=None, qualname=None, type=None, start=1)`
:   Enumeration of Leighton-Micali Signatures (LMS) algorithm types, see rfc8554.
    
    Attributes
    ----------
    H : Hashfunction
    m : Outputlength of the hashfunction
    h : height of the tree

    ### Ancestors (in MRO)

    * enum.Enum

    ### Class variables

    `LMS_SHA256_M32_H10`
    :

    `LMS_SHA256_M32_H15`
    :

    `LMS_SHA256_M32_H20`
    :

    `LMS_SHA256_M32_H25`
    :

    `LMS_SHA256_M32_H5`
    :

    ### Instance variables

    `H`
    :

    `h`
    :

    `m`
    :

`LMS_Priv(typecode, otstypecode, num_cores=None)`
:   A class used to generate the private key and derive the public key of Leighton-Micali Signatures (LMS)
    
    Methods
    -------
    sign(message)
        signs the message with the private key associated with the class
    gen_pub
        computes the public key, i.e. an instance of LM_OTS_Pub
    
    Parameters
    ----------
    typecode    : LMS_ALGORITHM_TYPE
    otstypecode : LMOTS_ALGORITHM_TYPE
    num_cores   : int | None (default)
        the number of CPU cores used for key generation, None=all cores

    ### Methods

    `calc_K(x)`
    :

    `calc_hash(H, *l)`
    :

    `gen_pub(self)`
    :   Computes the public key associated with the private key in this class.
        
        Returns
        ------
        an instance of LMS_Pub

    `get_avail_signatures(self)`
    :

    `sign(self, message)`
    :   Signs the message with the private key associated with the class.
        
        Parameters
        ----------
        message : bstr
        
        Raises:
        FAILURE
            if private keys are exhausted
        
        Returns
        ------
        signature

`LMS_Pub(pubkey)`
:   A class used to hold the public key of Leighton-Micali Signatures (LMS)
    
    Methods
    -------
    verify(message, signature)
        tries to verify the signature of a message with the public key associated with the class

    ### Methods

    `algo6b(self, message, signature)`
    :

    `get_pubkey(self)`
    :

    `len_pubkey(pubkey)`
    :

    `len_signature(signature)`
    :

    `verify(self, message, signature)`
    :   Tries to verify the signature of a message with the public key associated with the class.
        
        Parameters
        ----------
        message : bstr
        signature : bstr
        
        Raises
        ------
        INVALID
            If signature is invalid.

`LM_OTS_Priv(typecode, I, q)`
:   A class used to generate the private key and derive the public key of Leighton-Micali One-Time-Signatures (LMOTS)
    
    Methods
    -------
    sign(message)
        signs the message with the private key associated with the class
    gen_pub
        computes the public key, i.e. an instance of LM_OTS_Pub
    
    Parameters
    ----------
    typecode : LMOTS_ALGORITHM_TYPE
    I        : bstr (16 random bytes)
    q        : int

    ### Methods

    `gen_pub(self)`
    :   Computes the public key associated with the private key in this class.
        
        Returns
        ------
        an instance of LM_OTS_Pub

    `sign(self, message)`
    :   Signs the message with the private key associated with the class.
        
        Parameters
        ----------
        message : bstr
        
        Raises:
        FAILURE
            if a signature has already been computed
        
        Returns
        ------
        signature

`LM_OTS_Pub(pubkey)`
:   A class used to hold the public key of Leighton-Micali One-Time-Signatures (LMOTS)
    
    Methods
    -------
    verify(message, signature)
        tries to verify the signature of a message with the public key associated with the class
    
    Parameters
    ----------
    pubkey : bstr
        typecode || I || q || K

    ### Methods

    `algo4b(self, message, signature)`
    :

    `verify(self, message, signature)`
    :   Tries to verify the signature of a message with the public key associated with the class.
        
        Parameters
        ----------
        message : bstr
        signature : bstr
        
        Raises
        ------
        INVALID
            If signature is invalid.

`PersHSS_Priv(lmstypecodes, otstypecode, filename, password, frequence)`
:   A class derived from HSS_Priv. It is used to generate the private key and
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
    
    Parameters
    ----------
    lmstypecodes : List of LMS_ALGORITHM_TYPE
    otstypecode  : LMOTS_ALGORITHM_TYPE
    filename     : str, holds the name of the file to store the key
    password     : bstr, password to sign and encrypt the file
    frequence    : frequnce at which the key is stored to a file

    ### Ancestors (in MRO)

    * hsslms.hss.HSS_Priv

    ### Methods

    `from_file(filename, password)`
    :   A key, HSS_Priv, is loaded from a password-protected file.
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

    `save(self)`
    :   The key is saved.

    `sign(self, message)`
    :   Signs the message with the private key associated with the class.
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
