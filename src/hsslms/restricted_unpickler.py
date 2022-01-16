# -*- coding: utf-8 -*-
"""This module is for safe unpickling a HSS Private Key.
"""
import pickle
import io
import hsslms
import hashlib

class RestrictedUnpickler(pickle.Unpickler):
    """Safe unpickle a HSS Private Key
    """
    def find_class(self, module, name):
        safe_hsslms_pershss = ('PersHSS_Priv', )
        safe_hsslms_hss = ('HSS_Priv', )
        safe_hsslms_utils = ('LMS_ALGORITHM_TYPE', 'LMOTS_ALGORITHM_TYPE')
        safe_hsslms_lms = ('LMS_Priv', 'LMS_Pub')
        safe_hsslms_lmots = ('LM_OTS_Priv', )
        if module == 'hsslms.pershss' and name in safe_hsslms_pershss:
            return getattr(hsslms.pershss, name)
        if module == 'hsslms.hss' and name in safe_hsslms_hss:
            return getattr(hsslms.hss, name)
        if module == 'hsslms.utils' and name in safe_hsslms_utils:
            return getattr(hsslms.utils, name)
        if module == 'hsslms.lms' and name in safe_hsslms_lms:
            return getattr(hsslms.lms, name)
        if module == 'hsslms.lmots' and name in safe_hsslms_lmots:
            return getattr(hsslms.lms, name)
        if module == '_hashlib' and 'sha256' in name:
            return getattr(hashlib, 'sha256')
        # Forbid everything else.
        raise pickle.UnpicklingError("module '%s with name %s' is forbidden" %
                                     (module, name))

def restricted_loads(s):
    """Helper function analogous to pickle.loads()."""
    return RestrictedUnpickler(io.BytesIO(s)).load()