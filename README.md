# python-hsslms

This is an implementation of Leighton-Micali Hash-Based Signatures in Python according to [RFC 8554](https://www.rfc-editor.org/rfc/rfc8554.html).

The implementation is meant as a reference and for educational purposes.

The implementation provides 4 classes:
 * LM-OTS One-Time Signatures. These are one-time signatures; each private key MUST be used at most one time to sign a message.
 * Leighton-Micali Signatures (LMS). This system holds a fixed number of one-time signatures, i.e. LM-OTS.
 * Hierarchical Signatures (HSS). This system uses a sequence of LMS.
 * Persistent Hierarchical Signatures (PersHSS). The same as HSS except that the private key is stored in an encrypted file.

## Example Usage
#### LM-OTS
```python
# generate a one-time private key
sk = LM_OTS_Priv(LMOTS_ALGORITHM_TYPE.LMOTS_SHA256_N32_W2, urandom(16), 0)
# sign a message with the private key
signature = sk.sign(b'abc')
# compute the related public key
vk = sk.gen_pub()
# verify the signature, if invalid an exception will be raised
vk.verify(b'abc', signature)
```
#### LMS
```python
# generate a private key
sk = LMS_Priv(LMS_ALGORITHM_TYPE.LMS_SHA256_M32_H10, LMOTS_ALGORITHM_TYPE.LMOTS_SHA256_N32_W8)
# sign a message with the private key, in total 2^10 signatures are available
signature = sk.sign(b'abc')
# compute the related public key
vk = sk.gen_pub()
# verify the signature, if invalid an exception will be raised
vk.verify(b'abc', signature)
```

#### HSS
```python
# generate a private key
sk = HSS_Priv([LMS_ALGORITHM_TYPE.LMS_SHA256_M32_H10]*2, LMOTS_ALGORITHM_TYPE.LMOTS_SHA256_N32_W1)
# sign a message with the private key, in total 2^20 signatures are available
signature = sk.sign(b'abc')
# compute the related public key
vk = sk.gen_pub()
# verify the signature, if invalid an exception will be raised
vk.verify(b'abc', signature)
```

## Performance Measurements
The measurements are done on a Ryzen 5800X, where multiprocessing features are used with 6 cores.

#### Key Generation
| Key-Type   | w     | Time[s]            | #Signatures   | Size of Signature   |
|------------|-------|--------------------|--------------:|--------------------:|
| H10        | 1/2/8 | 0.5 / 0.3 / 0.9    | 1024          | 8848 /
| H15        | 1/2/8 | 15.7/9.5/23.3      | 32768         | 9008 /
| H20        | 1/2/8 | - / - / 806        | 1048576       | - / - /
| H10/H10    | 1/2/8 | 1.4 / 0.7 / 3.2    | 1048576       | 17748 / 9300 / 2964
| H10/H15    | 1/2/8 | 6.0 / 9.7 / 24.5   | 33554432      | 17908 / 9460 / 3124
| H15/H15    | 1/2/8 | 12.9 / 14.0 / 50.8 | 1073741824    | 18068 / 9620 /


#### Performance of Signature Generation:
| Key-Type   | w     | Time[s]              |
|------------|-------|----------------------|
| H15        | 1/2/8 | 0.04 / 0.01 / 0.005  |


#### Performance of Signature Verification:
| Key-Type   | w     | Time[s]              |
|------------|-------|----------------------|
| H15        | 1/2/8 | 0.04 / 0.01 / 0.005  |


# License
[MIT](https://opensource.org/licenses/MIT)