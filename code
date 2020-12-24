import requests
import hashlib
import sys
###Must also install the library 'requests' by doing "pip3 install requests"###

###API function to receive data###
def request_api_data(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)
    if res.status_code != 200:
        raise RunTimeError(f'Error fetching: {res.status_code}. Please check the API and try again.')
    return res

###Function to count the amount of times the password entered has been found in the API###
def password_leak_count(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0

###Function that hashes the password entered in sha1: prevents users from seeing the full hash by only revealing the first five digits###
def pwned_api_check(pwd):
    sha1password = hashlib.sha1(pwd.encode('utf-8')).hexdigest().upper()
    first5_char, tail = sha1password[:5], sha1password[5:]
    response = request_api_data(first5_char)
    return password_leak_count(response, tail)

#main function to use the passwordchecker
def main(*args):
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(f'{password} was found {count} times in the API. Consider changing your password.')
        else:
            print(f'{password} could not be found.')
    return 'Done!'

