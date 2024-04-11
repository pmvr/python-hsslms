Welcome to HssLms's documentation!
==================================

This is an implementation of Leighton-Micali Hash-Based Signatures in Python according to `RFC 8554 <https://www.rfc-editor.org/rfc/rfc8554.html>`_.

The implementation is meant as a reference and for educational purposes.

The module  :py:mod:`hsslms` provides 5 classes:
 * :py:mod:`hsslms.lmots`: LM-OTS One-Time Signatures. These are one-time signatures; each private key MUST be used at most one time to sign a message.
 * :py:mod:`hsslms.lms`: Leighton-Micali Signatures (LMS). This system holds a fixed number of one-time signatures, i.e. LM-OTS.
 * :py:mod:`hsslms.hss`: Hierarchical Signatures (HSS). This system uses a sequence of LMS.
 * :py:mod:`hsslms.pershss`: Persistent Hierarchical Signatures (PersHSS). The same as HSS except that the private key is stored in an encrypted file.
 * :py:mod:`hsslms.lmswrapper`: LMS_Wrapper_Priv. Generates a private key and derives the public key of a LMS signature system.  The private key is signed and stored in an encrypted file.


Example Usage
=============
LM-OTS
------
.. code-block:: python

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

LMS
---
.. code-block:: python

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

HSS
---
.. code-block:: python

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

Command Line Interface
----------------------
This module comes with an command line interface. Example usage:

.. code-block:: text

    > hsslms --help
    usage: __main__.py [-h] {key-gen,pubkey-gen,sign,verify,sk-info,vk-info} ...

    Hierarchical Signature System of Leighton-Micali Hash-Based Signatures according to RFC 8554

    optional arguments:
      -h, --help            show this help message and exit

    commands:
      availabel commands

      {key-gen,pubkey-gen,sign,verify,sk-info,vk-info}


.. toctree::
   :maxdepth: 2
   :caption: Contents:

   modules


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
