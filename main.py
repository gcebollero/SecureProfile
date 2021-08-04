import json
import sys
from typing import List
import os
from Crypto.Cipher import AES
from hashlib import sha256
from getpass import getpass


def _load_profiles() -> dict:
    """
    This function loads the profile file from disk
    :return: A dictionary with the profiles
    """
    if os.path.exists('profiles'):
        # return the contents
        _contents = open('profiles', 'r').read()
        return json.loads(_contents)
    else:
        # If no file available, return an empty dictionary
        return {}


def _write_profiles(profiles_data: dict) -> None:
    """
    This function saves the profile file to disk
    :return: None
    """
    _profiles_file = open('profiles', 'w')
    _profiles_file.write(json.dumps(profiles_data))


def _encrypt(data: str, key: str) -> List:
    """
    This functions encrypts with AES the data string using the key string
    :param data: Data to be encrypted
    :param key: Key for encryption
    :return: [ Nonce, CipherText, MAC Tag ]
    """
    # Instantiate the cipher int EAX mode
    cipher = AES.new(key.encode('UTF-8'), AES.MODE_EAX)
    # Obtain the nonce
    nonce = cipher.nonce
    # Obtain the ciphertext and the tag
    ciphertext, tag = cipher.encrypt_and_digest(data.encode('UTF-8'))
    print([nonce.hex(), ciphertext.hex(), tag.hex()])
    return [nonce.hex(), ciphertext.hex(), tag.hex()]


def save_new_profile(**kwargs) -> None:
    """
    This function stored a username and password in a profile. If the profile already exists, it will be overwritten.
    If not arguments are found, they will be asked by the CLI
    :param kwargs: Accepted values ['profile_name, 'profile_password', 'username', 'password']
    :return: tuple(username, password)
    """
    # Load the profiles previously saved
    _profiles = _load_profiles()
    _hashlib = sha256()
    # Obtain the profile name from arguments or request it by the terminal
    _profile_name = kwargs['profile_name'] if 'profile_name' in kwargs else input('New profile name: ')
    # Calculate the SHA256 of the profile
    _hashlib.update(_profile_name.encode('UTF-8'))
    _profile_name = _hashlib.hexdigest()
    if _profile_name in _profiles:
        print('Profile already exists. It will be overwritten. ', file=sys.stderr)
    # Obtain the profile password from arguments or request it by the terminal
    _hashlib = sha256()
    _profile_password = kwargs['profile_password'] if 'profile_password' in kwargs else getpass('Profile password: ')
    _hashlib.update(_profile_password.encode('UTF-8'))
    # AES does not support keys of 32+ bytes, trim the hex string
    _profile_password = _hashlib.hexdigest()[:32]
    # Obtain the username from arguments or request it by the terminal and encrypt it
    _username = _encrypt(kwargs['username'] if 'username' in kwargs else input('Username: '), _profile_password)
    # Obtain the password from arguments or request it by the terminal and encrypt it
    _password = _encrypt(kwargs['password'] if 'password' in kwargs else getpass('Password: '), _profile_password)
    # Update profile file
    _profiles[_profile_name] = {0: _username, 1: _password}
    # Update file
    _write_profiles(profiles_data=_profiles)


def get_username_password_from_profile(**kwargs) -> tuple:
    """
    This function retrieves a username and password from a saved profile if the password match.
    If not arguments are found, they will be asked by the CLI
    :param kwargs: Accepted values ['profile_name, 'profile_password']
    :return: tuple(username, password)
    """
    _profiles = _load_profiles()
    _hashlib = sha256()
    # Obtain the profile name from arguments or request it by the terminal
    _profile_name = kwargs['profile_name'] if 'profile_name' in kwargs else input('Profile name: ')
    # Calculate the SHA256 of the profile
    _hashlib.update(_profile_name.encode('UTF-8'))
    _profile_name = _hashlib.hexdigest()
    if _profile_name not in _profiles:
        raise ValueError('Profile name not found')
    # Obtain the profile password from arguments or request it by the terminal
    _hashlib = sha256()
    _profile_password = kwargs['profile_password'] if 'profile_password' in kwargs else getpass(
        'Profile password: ')
    _hashlib.update(_profile_password.encode('UTF-8'))
    # AES does not support keys of 32+ bytes, trim the hex string
    _profile_password = _hashlib.hexdigest()[:32]
    # Decrypt the username
    _cipher = AES.new(_profile_password.encode('UTF-8'), AES.MODE_EAX,
                      nonce=bytearray.fromhex(_profiles[_profile_name]['0'][0]))
    _username_plaintext = _cipher.decrypt(bytearray.fromhex(_profiles[_profile_name]['0'][1]))
    try:
        _cipher.verify(bytearray.fromhex(_profiles[_profile_name]['0'][2]))
    except ValueError:
        raise ValueError("Key incorrect or message corrupted")
    # Decrypt the password
    _cipher = AES.new(_profile_password.encode('UTF-8'), AES.MODE_EAX,
                      nonce=bytearray.fromhex(_profiles[_profile_name]['1'][0]))
    _password_plaintext = _cipher.decrypt(bytearray.fromhex(_profiles[_profile_name]['1'][1]))
    try:
        _cipher.verify(bytearray.fromhex(_profiles[_profile_name]['1'][2]))
    except ValueError:
        raise ValueError("Key incorrect or message corrupted")
    return _username_plaintext.decode('UTF-8'), _password_plaintext.decode('UTF-8')
