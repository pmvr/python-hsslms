#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Thu Dec 23 09:14:46 2021

@author: mvr

https://www.rfc-editor.org/rfc/rfc8554.html
"""

import time
from hsslms import LMOTS_ALGORITHM_TYPE, HSS_Priv, LMS_ALGORITHM_TYPE

def perf_keygen(lmstypecodes, otstypecode, num_cores):
    start = time.time()
    _ = HSS_Priv(lmstypecodes, otstypecode, num_cores)
    return time.time() - start
    

# Testing Performance of HSS
num_cores = 6
for lmots_alg in LMOTS_ALGORITHM_TYPE:
    w = lmots_alg.w
    print("Performance of HSS-LMS with w=%d:" % w)
    print("--------------------------------")
    
    print("  Performance of Key Generation:")
    print("           %10s %15s" %('Time[s]', '#Signatures'))
    
    duration = perf_keygen([LMS_ALGORITHM_TYPE.LMS_SHA256_M32_H10], lmots_alg, num_cores)
    print("      H10: %10.2f %15d" % (duration, 2**10))
    duration = perf_keygen([LMS_ALGORITHM_TYPE.LMS_SHA256_M32_H15], lmots_alg, num_cores)
    print("      H15: %10.2f %15d" % (duration, 2**15))
    duration = perf_keygen([LMS_ALGORITHM_TYPE.LMS_SHA256_M32_H20], lmots_alg, num_cores)
    print("      H20: %10.2f %15d" % (duration, 2**20))
    duration = perf_keygen([LMS_ALGORITHM_TYPE.LMS_SHA256_M32_H10,LMS_ALGORITHM_TYPE.LMS_SHA256_M32_H10], lmots_alg, num_cores)
    print("  H10/H10: %10.2f %15d" % (duration, 2**10 * 2**10))
    duration = perf_keygen([LMS_ALGORITHM_TYPE.LMS_SHA256_M32_H10,LMS_ALGORITHM_TYPE.LMS_SHA256_M32_H15], lmots_alg, num_cores)
    print("  H10/H15: %10.2f %15d" % (duration, 2**10 * 2**15))
    duration = perf_keygen([LMS_ALGORITHM_TYPE.LMS_SHA256_M32_H15,LMS_ALGORITHM_TYPE.LMS_SHA256_M32_H15], lmots_alg, num_cores)
    print("  H15/H15: %10.2f %15d" % (duration, 2**15 * 2**15))
    
    print()
    print("  Performance of Signature Generation:")
    print("           %10s" % 'Time[s]')
    sk = HSS_Priv([LMS_ALGORITHM_TYPE.LMS_SHA256_M32_H15], lmots_alg, num_cores)
    duration = 0.0
    for _ in range(1000):
        start = time.time()
        _ = sk.sign(b'abc')
        duration += time.time() - start
    duration /= 1000
    print("      H15: %10.3f" % duration)
    
    print()
    print("  Performance of Signature Verification:")
    print("           %10s" % 'Time[s]')
    sk = HSS_Priv([LMS_ALGORITHM_TYPE.LMS_SHA256_M32_H15], lmots_alg, num_cores)
    vk = sk.gen_pub()
    duration = 0.0
    for _ in range(1000):
        signature = sk.sign(b'abc')
        start = time.time()
        vk.verify(b'abc', signature)
        duration += time.time() - start
    duration /= 1000
    print("      H15: %10.3f" % duration)
    print()
    print()
    