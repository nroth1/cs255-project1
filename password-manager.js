"use strict";



/********* External Imports ********/

var lib = require("./lib");

var KDF = lib.KDF,
    HMAC = lib.HMAC,
    SHA256 = lib.SHA256,
    setup_cipher = lib.setup_cipher,
    enc_gcm = lib.enc_gcm,
    dec_gcm = lib.dec_gcm,
    bitarray_slice = lib.bitarray_slice,
    bitarray_to_string = lib.bitarray_to_string,
    string_to_bitarray = lib.string_to_bitarray,
    bitarray_to_hex = lib.bitarray_to_hex,
    hex_to_bitarray = lib.hex_to_bitarray,
    bitarray_to_base64 = lib.bitarray_to_base64,
    base64_to_bitarray = lib.base64_to_bitarray,
    byte_array_to_hex = lib.byte_array_to_hex,
    hex_to_byte_array = lib.hex_to_byte_array,
    string_to_padded_byte_array = lib.string_to_padded_byte_array,
    string_to_padded_bitarray = lib.string_to_padded_bitarray,
    string_from_padded_byte_array = lib.string_from_padded_byte_array,
    string_from_padded_bitarray = lib.string_from_padded_bitarray,
    random_bitarray = lib.random_bitarray,
    bitarray_equal = lib.bitarray_equal,
    bitarray_len = lib.bitarray_len,
    bitarray_concat = lib.bitarray_concat,
    dict_num_keys = lib.dict_num_keys;


/********* Implementation ********/


var keychain = function() {
  // Class-private instance variables.
  var priv = {
    secrets: { SHA_hash:'',salt:'', 
            auth_message:'', auth_cipher_text:'', 
            key_HMAC_message:'', key_GCM_message:'' },
    data: {  }
  };

  // Maximum length of each record in bytes
  var MAX_PW_LEN_BYTES = 64;
  var HMAC_LENGTH = -1;
  var MINIMUM_PAD_LEGNTH = 1; 
  
  // Flag to indicate whether password manager is "ready" or not
  var ready = false;

  var keychain = {};

  /** 
    * Creates an empty keychain with the given password. Once init is called,
    * the password manager should be in a ready state.
    *
    * Arguments:
    *   password: string
    * Return Type: void
    */
  keychain.init = function(password) {  /*N*/
    ready = true;
    priv.secrets = {}
    priv.data = {}
    priv.data.salt = lib.random_bitarray(128); 
    var master_key = lib.KDF(password,priv.data.salt);
    //priv.secrets.auth_message = "Authenticated correctly";
     
    priv.secrets.key_HMAC_message = bitarray_slice(lib.HMAC(master_key,"HMAC TO KEY"),0,128);
    priv.secrets.key_GCM_message = bitarray_slice(lib.HMAC(master_key,"GCM TO KEY"),0,128);
    //var cipher = lib.setup_cipher(bitarray_slice(master_key,0,128));
    console.log( priv.secrets.key_GCM_message   )
    priv.secrets.version = "CS 255 Password Manager v1.0";
  };

  /**
    * Loads the keychain state from the provided representation (repr). The
    * repr variable will contain a JSON encoded serialization of the contents
    * of the KVS (as returned by the save function). The trusted_data_check
    * is an *optional* SHA-256 checksum that can be used to validate the 
    * integrity of the contents of the KVS. If the checksum is provided and the
    * integrity check fails, an exception should be thrown. You can assume that
    * the representation passed to load is well-formed (e.g., the result of a 
    * call to the save function). Returns true if the data is successfully loaded
    * and the provided password is correct. Returns false otherwise.
    *
    * Arguments:
    *   password:           string
    *   repr:               string
    *   trusted_data_check: string
    * Return Type: boolean
    */
  keychain.load = function(password, repr, trusted_data_check) { /*H*/
    /* generate the main KEY from the given password. */
    key = KDF(passowrd, salt);

    /* check the correctness of the main KEY. */
    cipher = setup_cipher(key);
    console.log(bitarray_len(key))

    if (enc_gcm(cipher, auth_message) != auth_cipher_text) return false;

    /* check the integrity of KVS data. */
    if (trusted_data_check) {
        /* noraml way: compute the checksum of the repr string and compare it with the 
        provided SHA-256 hash. */
        hash_value = SHA256(string_to_bitarray(repr))
        if (hash_value != trusted_data_check) throw "INVALID REPR!";
        
        /* extra credit: encrypt the counter concatenated with the repr string, compute
        the checksum of the cipher text and compare it with the stored SHA-256 hash. */
        // text = bitarray_concat(string_to_bitarray(trusted_data_check), string_to_bitarray(repr));
        // hash_value = SHA256(enc_gcm(cipher, text));
        // if (hash_value != priv.secrets.SHA_hash) throw "INVALID REPR!";
    }

    /* parse the jason into keycahin. */    
    keychain = JSON.parse(repr)
    ready = true;

    return true;
  };

  /**
    * Returns a JSON serialization of the contents of the keychain that can be 
    * loaded back using the load function. The return value should consist of
    * an array of two strings:
    *   arr[0] = JSON encoding of password manager
    *   arr[1] = SHA-256 checksum
    * As discussed in the handout, the first element of the array should contain
    * all of the data in the password manager. The second element is a SHA-256
    * checksum computed over the password manager to preserve integrity. If the
    * password manager is not in a ready-state, return null.
    *
    * Return Type: array
    */ 
  keychain.dump = function() { /*N*/
    throw "Not implemented!";
  }

  /**
    * Fetches the data (as a string) corresponding to the given domain from the KVS.
    * If there is no entry in the KVS that matches the given domain, then return
    * null. If the password manager is not in a ready state, throw an exception. If
    * tampering has been detected with the records, throw an exception.
    *
    * Arguments:
    *   name: string
    * Return Type: string
    */
  keychain.get = function(name) { /*H*/
    	if(ready){
		console.log(name)
		var domain_key = priv.secrets.key_HMAC_message; 
   		var value_key = priv.secrets.key_GCM_message;
    		var domain_HMAC = lib.HMAC(domain_key,name); 
		if(!(domain_HMAC in priv.data )){
			return null;	
		}
		var encrypted = priv.data[domain_HMAC];
		//console.log(encrypted);
		console.log(name);
		var plain_bits = dec_gcm(setup_cipher(value_key),encrypted);
	 	var password_padded = bitarray_slice(plain_bits,0,(65+4)*8);
		console.log(bitarray_len(password_padded))	
		console.log(password_padded.length) 
		var password_text = string_from_padded_bitarray(password_padded,65);
		console.log(bitarray_slice(plain_bits,(65+4)*8,bitarray_len(plain_bits)))
		console.log(bitarray_len(domain_HMAC))
		console.log(bitarray_len(plain_bits))
		if(! bitarray_equal(domain_HMAC,bitarray_slice(plain_bits,(65+4)*8,bitarray_len(plain_bits)))){
			throw 'SWAPPING ATTACK DETECTED'
		}
		return password_text	
	}else{
		throw "NOT READY"
	}
  }

  /** 
  * Inserts the domain and associated data into the KVS. If the domain is
  * already in the password manager, this method should update its value. If
  * not, create a new entry in the password manager. If the password manager is
  * not in a ready state, throw an exception.
  *
  * Arguments:
  *   name: string
  *   value: string
  * Return Type: void
  */
  keychain.set = function(name, value) { /*N*/
    if(ready){
    	 var domain_key = priv.secrets.key_HMAC_message; 
   	 var value_key = priv.secrets.key_GCM_message;
    	 var domain_HMAC = lib.HMAC(domain_key,name);
         var val_bits = string_to_padded_bitarray(value,65);
	 var name_bits = domain_HMAC;
	 //var signed_data = val_bits 
	 var signed_data = bitarray_concat(val_bits,name_bits);
	 var encrypted_data = enc_gcm(setup_cipher( value_key ) , signed_data);
	 priv.data[domain_HMAC] = encrypted_data ;
    }else{
    	throw "NOT READY"
    }
    //throw "Not implemented!";
  }

  /**
    * Removes the record with name from the password manager. Returns true
    * if the record with the specified name is removed, false otherwise. If
    * the password manager is not in a ready state, throws an exception.
    *
    * Arguments:
    *   name: string
    * Return Type: boolean
  */
  keychain.remove = function(name) { /*H*/
  
  }

  return keychain;
}

module.exports.keychain = keychain;
