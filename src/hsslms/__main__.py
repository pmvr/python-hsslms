#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Wed Jan 12 12:39:29 2022

@author: mvr
"""
import sys
from os import cpu_count
from pathlib import Path
import getpass
import argparse
from hsslms.utils import LMOTS_ALGORITHM_TYPE, LMS_ALGORITHM_TYPE, FAILURE, INVALID
from hsslms import PersHSS_Priv, HSS_Pub

def main():
    parser = argparse.ArgumentParser(description='Hierarchical Signature System of Leighton-Micali Hash-Based Signatures according to RFC 8554')
    subparsers = parser.add_subparsers(title='commands', description='availabel commands', dest='cmd')
    
    parser_keygen = subparsers.add_parser('key-gen', description='generate a key pair')
    parser_keygen.add_argument('--lmots', choices=('LMOTS_SHA256_N32_W1', 'LMOTS_SHA256_N32_W2', 'LMOTS_SHA256_N32_W4', 'LMOTS_SHA256_N32_W8'), dest='lmots', required=True, help='lmots parameter set')
    parser_keygen.add_argument('--lms', choices=('LMS_SHA256_M32_H5', 'LMS_SHA256_M32_H10', 'LMS_SHA256_M32_H15', 'LMS_SHA256_M32_H20', 'LMS_SHA256_M32_H25'), dest='lms', nargs='+', required=True, help='lms parameter set')
    parser_keygen.add_argument('--out', '-o', help='filename of private key, ".pub" is appended to the filename of the pubklic key', required=True, dest='out')
    parser_keygen.add_argument('--password', '-p', help='password to encrypt the private key', required=False, dest='password')
    parser_keygen.add_argument('--cores', '-c', help='numer of cpu cores for computation (default=2)', type=int, default=2, choices=range(1,cpu_count()+1), required=False, dest='num_cores')
    
    parser_keygen = subparsers.add_parser('pubkey-gen', description='generate the public form a private key')
    parser_keygen.add_argument('--in', '-i', help='filename of private key', required=True, dest='infile')
    parser_keygen.add_argument('--password', '-p', help='password to decrypt the private key', required=False, dest='password')
    parser_keygen.add_argument('--out', '-o', help='filename of public key, if not present, the filename of the private key is used where ".pub" is appended', required=False, dest='out')

    parser_sign = subparsers.add_parser('sign')
    parser_sign.add_argument('--key', '-k', help='filename of the private key', required=True, dest='fn_key')
    parser_sign.add_argument('--password', '-p', help='password to decrypt the private key', required=False, dest='password')
    parser_sign.add_argument('-m', '--message', help='filename of a message to sign, -- means stdin', required=True, dest='fn_message')
    parser_sign.add_argument('-s', '--signature', help='filename of the signature', required=True, dest='fn_signature')
    
    parser_verfiy = subparsers.add_parser('verify')
    parser_verfiy.add_argument('--key', '-k', help='filename of the public key', required=True, dest='fn_key')
    parser_verfiy.add_argument('-m', '--message', help='filename of the message, -- means stdin', required=True, dest='fn_message')
    parser_verfiy.add_argument('-s', '--signature', help='filename of the signature', required=True, dest='fn_signature')
    
    parser_skinfo = subparsers.add_parser('sk-info')
    parser_skinfo.add_argument('--key', '-k', help='filename of the private key', required=True, dest='fn_key')
    parser_skinfo.add_argument('--password', '-p', help='password to decrypt the private key', required=False, dest='password')
    
    parser_vkinfo = subparsers.add_parser('vk-info')
    parser_vkinfo.add_argument('--key', '-k', help='filename of the public key', required=True, dest='fn_key')
    
    args = parser.parse_args()
    
    
    if args.cmd == 'key-gen':
        lmotstype = LMOTS_ALGORITHM_TYPE[args.lmots]
        lmstypes = [LMS_ALGORITHM_TYPE[t] for t in args.lms]
        if Path(args.out).exists():
            print('File "%s" already exists. Exit.' % args.out, file=sys.stderr)
            sys.exit(1)
        if Path(args.out+'.pub').exists():
            print('File "%s.pub" already exists. Exit.' % args.out, file=sys.stderr)
            sys.exit(1)
        if args.password is None:
            password = getpass.getpass(prompt='Please enter a password: ')
            password_check = getpass.getpass(prompt='Please reenter the password: ')
            if password != password_check:
                print('Passwords to not match. Exit.', file=sys.stderr)
                sys.exit(1)
        else:
            password = args.password
        sk = PersHSS_Priv(lmstypes, lmotstype, args.out, password.encode(sys.getdefaultencoding()), 1, args.num_cores)
        try:
            sk.save()
        except FAILURE as e:
            print(e, file=sys.stderr)
            sys.exit(1)
        vk = sk.gen_pub()
        try:
            with open(args.out+'.pub', 'wb') as fout:
                fout.write(vk.get_pubkey())
        except IOError:
            print("File %s cannot be saved." % (args.out+'.pub',), file=sys.stderr)
            sys.exit(1)
    elif args.cmd == 'pubkey-gen':
        if not Path(args.infile).exists():
            print('File "%s" does not exist. Exit.' % args.infile, file=sys.stderr)
            sys.exit(1)
        if not args.out is None:
            fn_pub = args.out
        else:
            fn_pub = args.infile + '.pub'
        if Path(fn_pub).exists():
            print('File "%s" already exists. Exit.' % fn_pub, file=sys.stderr)
            sys.exit(1)
        if args.password is None:
            password = getpass.getpass(prompt='Please enter the password: ')
        else:
            password = args.password        
        try:
            sk = PersHSS_Priv.from_file(args.infile, password.encode(sys.getdefaultencoding()))
        except FAILURE as e:
            print(e, file=sys.stderr)
            sys.exit(1)
        vk = sk.gen_pub()
        try:
            with open(fn_pub, 'wb') as fout:
                fout.write(vk.get_pubkey())
        except IOError:
            print("File %s cannot be saved." % fn_pub, file=sys.stderr)
            sys.exit(1)            
    elif args.cmd == 'sign':
        if args.fn_message != '--':
            if not Path(args.fn_message).exists():
                print('File "%s" does not exist. Exit.' % args.fn_message, file=sys.stderr)
                sys.exit(1)
        if not Path(args.fn_key).exists():
            print('File "%s" does not exist. Exit.' % args.fn_key, file=sys.stderr)
            sys.exit(1)
        if Path(args.fn_signature).exists():
            print('File "%s" already exists. Exit.' % args.fn_signature, file=sys.stderr)
            sys.exit(1)
        if args.password is None:
            password = getpass.getpass(prompt='Please enter the password: ')
        else:
            password = args.password   
        try:
            sk = PersHSS_Priv.from_file(args.fn_key, password.encode(sys.getdefaultencoding()))
            if args.fn_message == '--':
                f_message = sys.stdin
            else:
                f_message = open(args.fn_message, 'rb')
            signature = sk.sign(f_message)
            with open(args.fn_signature, 'wb') as fout:
                fout.write(signature)          
        except FAILURE as e:
            print(e, file=sys.stderr)
            sys.exit(1)
        except IOError as e:
            print(e, file=sys.stderr)
            sys.exit(1)
    elif args.cmd == 'verify':
        if args.fn_message != '--':
            if not Path(args.fn_message).exists():
                print('File "%s" does not exist. Exit.' % args.fn_message, file=sys.stderr)
                sys.exit(1)
        for fn in (args.fn_key, args.fn_signature):
            if not Path(fn).exists():
                print('File "%s" does not exist. Exit.' % fn, file=sys.stderr)
                sys.exit(1)
        try:
            with open(args.fn_key, 'rb') as fin:
                pubkey = fin.read()
            with open(args.fn_signature, 'rb') as fin:
                signature = fin.read()
        except IOError as e:
            print(e, file=sys.stderr)
            sys.exit(1)
        try:
            vk = HSS_Pub(pubkey)
            if args.fn_message == '--':
                f_message = sys.stdin
            else:
                f_message = open(args.fn_message, 'rb')
            vk.verify(f_message, signature)
        except INVALID:
            print("Signature is invalid.", file=sys.stderr)
            sys.exit(1)
        except IOError as e:
            print(e, file=sys.stderr)
            sys.exit(1)
        print("Signature is valid.", file=sys.stderr)
    elif args.cmd == 'sk-info':
        if not Path(args.fn_key).exists():
            print('File "%s" does not exist. Exit.' % args.fn_key, file=sys.stderr)
            sys.exit(1)
        if args.password is None:
            password = getpass.getpass(prompt='Please enter the password: ')
        else:
            password = args.password   
        try:
            sk = PersHSS_Priv.from_file(args.fn_key, password.encode(sys.getdefaultencoding()))
            print(sk.info())
        except FAILURE as e:
            print(e, file=sys.stderr)
            sys.exit(1)        
    elif args.cmd == 'vk-info':
        if not Path(args.fn_key).exists():
            print('File "%s" does not exist. Exit.' % args.fn_key, file=sys.stderr)
            sys.exit(1)
        try:
            with open(args.fn_key, 'rb') as fin:
                pubkey = fin.read()
        except IOError as e:
            print(e, file=sys.stderr)
            sys.exit(1)
        try:
            vk = HSS_Pub(pubkey)
            print(vk.info())
        except INVALID:
            print("Public Key is invalid.", file=sys.stderr)
            sys.exit(1)
    
if __name__ == "__main__":
    main()