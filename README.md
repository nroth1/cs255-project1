# CS255-project1
Nat Roth, Yanshu Hong

### Implementation Thoughts

1. For generating keys from the master password, can we reuse the same key for both the HMAC and for encrpyting the values? 
 - I'm not sure about this. I guess probably not. I took a look at the PBKDF2 function and it takes a password and a salt. So salt is generally a random integer, but I guess a different (salt, password) pair is going to derive a different key. So are we going to store the salt in the database? (we have to reuse the same salt) And if we use two different salts, we can have two different keys derived from the same password.
 - Are we going to store the derived key in the database? Or, how can we make sure the user enters the right master password? I'm thinking about saving the salts explictly and saving keys encryted under themselves. So when ther user enters the master password, we derive two keys that can decrypt the "right keys". If the decrypted "keys" are the same as the keys we use to decrypt, we know the user entered the right master password. The question is, IS THIS SECURE?

2. What's the best way to avoid leaking length of encrypted passwords (padding, I guess?) 
 - Padding to 64bits? Padding one 1 and all 0s?

3. What's the best way to guard against swap + rollback attacks? For swapping, seems like you might want to somehow sign the password with the domain it belongs to. That won't help for rollbacks, though. For rollbacks, is it just as simple as comparing the KVS state to the previously hashed SHA-256 version? 
 - I agree with you. For swapping, we can auth encrypt "HMAC(domain)||password" and every time we decrypt, we have to assert that the decrypted HMAC(domain) is actually the same as the explicit HMAC(DOMAIN). And becasue HMAC(DOMAIN) has a set length, it's easy to seperate it from the real passwords.
 - For rollbacks, just hash the entire dictionary using SHA-256? Yeah, probably.

**My main questions:**

 - How to authenticate the master password?

 - How to pad HMAC||password to a given length?

