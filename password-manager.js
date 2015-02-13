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
    secrets: { salt:"", key_AUTH_message:"", key_HMAC_message:"", key_GCM_message:""},
    data:    { }
  };

  // Maximum length of each record in bytes
  var MAX_PW_LEN_BYTES = 64;
  var EXTRA_PADDING_BYTES = 4;
  var TOTAL_PASSWORD_LENGTH = MAX_PW_LEN_BYTES + 1 + EXTRA_PADDING_BYTES;
  var AES_KEY_LENGTH_BITS = 128;
  var MAC_KEY_LENGTH_BITS = 256;

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
    ready = false;

    priv.secrets = {};
    priv.data = {};
    priv.secrets.version = "CS 255 Password Manager v2.0";

    priv.secrets.salt = lib.random_bitarray(AES_KEY_LENGTH_BITS); 
    var master_key = lib.KDF(password, priv.secrets.salt);

    priv.secrets.key_AUTH_message = bitarray_slice(lib.HMAC(master_key,"AUTH TO KEY"), 0, AES_KEY_LENGTH_BITS);
    priv.secrets.key_HMAC_message = bitarray_slice(lib.HMAC(master_key,"HMAC TO KEY"), 0, MAC_KEY_LENGTH_BITS);
    priv.secrets.key_GCM_message  = bitarray_slice(lib.HMAC(master_key,"GCM TO KEY"),  0, AES_KEY_LENGTH_BITS);

    ready = true;
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
    ready = false;

    /* generate the main KEY from the given password. */ 
    var data = JSON.parse(repr);

    var salt = data["salt"];
    var master_key = lib.KDF(password,salt);
    var key_AUTH_message = bitarray_slice(lib.HMAC(master_key,"AUTH TO KEY"), 0, AES_KEY_LENGTH_BITS);

    /* check the correctness of the main KEY. */
    var cipher = setup_cipher(key_AUTH_message);
    try {
      var authenticated_output = dec_gcm(cipher, data["auth_message"]);  
    } catch(err) {
      return false;
    }   
    if (!bitarray_equal(authenticated_output, string_to_bitarray("AUTHENTICATE"))) return false;
    
    /* check the integrity of KVS data. */
    if (trusted_data_check) {
        /* noraml way: compute the checksum of the repr string and compare it with the 
        provided SHA-256 hash. */
        var hash_value = SHA256(string_to_bitarray(repr))
        if (!bitarray_equal(hash_value, trusted_data_check)) throw "REPR DOES NOT MATCH SHA256 HASH!!! LOOK OUT!!! TOUBLE AHEAD!!!";

        /* extra credit: encrypt the counter concatenated with the repr string, compute
        the checksum of the cipher text and compare it with the stored SHA-256 hash. */
        // text = bitarray_concat(string_to_bitarray(trusted_data_check), string_to_bitarray(repr));
        // hash_value = SHA256(enc_gcm(cipher, text));
        // if (!bitarray_equal(hash_value, repr["SHA_hash"])) throw "REPR DOES NOT MATCH SHA256 HASH!";
    }

    priv.secrets.salt = salt;
    priv.secrets.key_AUTH_message = key_AUTH_message;
    priv.secrets.key_HMAC_message = bitarray_slice(lib.HMAC(master_key,"HMAC TO KEY"), 0, MAC_KEY_LENGTH_BITS);
    priv.secrets.key_GCM_message = bitarray_slice(lib.HMAC(master_key,"GCM TO KEY"),   0, AES_KEY_LENGTH_BITS);

    /* parse the json into keycahin. */    
    priv.data = JSON.parse(repr);
    /* the salt and auth_message should not be stored in the data (kvs), instead they're in
    the secret object */
    delete priv.data["salt"];
    delete priv.data["auth_message"];
    // delete priv.data["SHA_hash"];

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
  	if (ready) {
  		/* Hacky way to make a deep copy of data map, since we don't want to add salt 
      and auth_message to data field.  */
  		var map_copy = JSON.parse(JSON.stringify(priv.data));
  		map_copy["salt"] = priv.secrets.salt;
  		map_copy["auth_message"] = enc_gcm(setup_cipher(priv.secrets.key_AUTH_message), string_to_bitarray("AUTHENTICATE"));

  		var SHA_hash = lib.SHA256(string_to_bitarray(JSON.stringify(map_copy)));
      // map_copy["SHA_hash"] = SHA_hash;

      /* return the tuple */
  		return [JSON.stringify(map_copy), SHA_hash];
    }
    return null;  
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
    if (ready) {
		  var domain_key = priv.secrets.key_HMAC_message; 
   	  var value_key = priv.secrets.key_GCM_message;
    	var domain_HMAC = lib.HMAC(domain_key, name); 
		  if(!(domain_HMAC in priv.data)) return null;	
		
      var encrypted = priv.data[domain_HMAC];
      var plain_bits = dec_gcm(setup_cipher(value_key), encrypted);
      var password_padded = bitarray_slice(plain_bits, 0, TOTAL_PASSWORD_LENGTH * 8);
      var password_text = string_from_padded_bitarray(password_padded, MAX_PW_LEN_BYTES + 1);
      if(! bitarray_equal(domain_HMAC, bitarray_slice(plain_bits, TOTAL_PASSWORD_LENGTH * 8, bitarray_len(plain_bits)))) {
        throw "SWAPPING ATTACK DETECTED!!! LOOK OUT!!! TOUBLE AHEAD!!!"
      }
      return password_text;
    } else {
      throw "Keychain not initialized.";
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
    if (ready) {
      var domain_key = priv.secrets.key_HMAC_message; 
      var value_key = priv.secrets.key_GCM_message;
      var domain_HMAC = lib.HMAC(domain_key,name);
      var val_bits = string_to_padded_bitarray(value, MAX_PW_LEN_BYTES + 1);
    	var name_bits = domain_HMAC;
    	
      var signed_data = bitarray_concat(val_bits, name_bits);
    	var encrypted_data = enc_gcm(setup_cipher(value_key), signed_data);
    	priv.data[domain_HMAC] = encrypted_data;
    } else {
      throw "Keychain not initialized.";
    }
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
  	if (ready) {
  		var domain_key = priv.secrets.key_HMAC_message; 
      var domain_HMAC = lib.HMAC(domain_key, name);
      
      if(domain_HMAC in priv.data) {
  			delete priv.data[domain_HMAC];
  			return true;
  		}

  		return false;
  	} else {
      throw "Keychain not initialized.";      
    }
  }

  return keychain;
}

module.exports.keychain = keychain;
