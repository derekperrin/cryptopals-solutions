from cryptopals import block

def profile_for(email: str) -> bytes:
    # We'll remove meta characters as the challenge suggests. We should probably make sure the email address
    # has exactly one @ character, but this isn't important for this exercise.
    email = email.replace('&','')
    email = email.replace('=','')
    return ('email=' + email + '&uid=10&role=user').encode()

if __name__ == '__main__':
    # Set our user email so the role of the resultant user profile is at the beginning of a 16 byte block.
    # To do this, we need len(email) + len('email&uid=10&role=') = 0 mod blocksize
    blocksize = 16
    print('Email length (Including the @ character) needs to be ', -len('email=&uid=10&role=') % blocksize)   
    user_profile = profile_for('tim@gmail.com') # length of this user profile is 36, so 'user' is in the last block.
    print(user_profile[-(len(user_profile)%blocksize):])

    # Now we can construct an email that will have 'admin' along with the proper padding and create
    # an email so that 'admin' + padding occupies an entire block. First let's find the length of the email to craft
    blocksize - len('email=')

    # So we'll create an email of length 10(we'll do 26 in this one), followed by 'admin' padded appropriately.
    chosen_plaintext = 'jupyter_notebook@gmail.com' + block.pkcs7(b'admin').decode()
    attack_profile = profile_for(chosen_plaintext)
    print(attack_profile[blocksize*2:blocksize*3])

    # Now finally, we will encrypt the user profile, the attack proflie, then splice them together appropriately and
    # show that we were able to create an admin user.
    key = block.gen_random_aes_key()
    encrypted_user = block.aes_ecb_encrypt(user_profile,key)
    encrypted_attacker = block.aes_ecb_encrypt(attack_profile,key)
    encrypted_user = encrypted_user[:-1*blocksize] + encrypted_attacker[blocksize*2:blocksize*3]
    print(block.aes_ecb_decrypt(encrypted_user,key))
