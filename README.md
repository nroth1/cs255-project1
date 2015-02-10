# CS255-project1
Nat Roth
Yanshu Hong

# Implementation Thoughts (Nat)

1. For generating keys from the master password, can we reuse the same key for both the HMAC and for encrpyting the values? 

2. What's the best way to avoid leaking length of encrypted passwords (padding, I guess?) 

3. What's the best way to guard against swap + rollback attacks? For swapping, seems like you might want to somehow sign the password with the domain it belongs to. That won't help for rollbacks, though. For rollbacks, is it just as simple as comparing the KVS state to the previously hashed SHA-256 version? 

