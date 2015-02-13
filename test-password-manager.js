"use strict";

var lib = require("./lib");

var random_bitarray = lib.random_bitarray;


function assert(condition, message) {
  if (!condition) {
    console.trace();
    throw message || "Assertion failed!";
  }
}

var password_manager = require("./password-manager");

var password = "password123!!";
var keychain = password_manager.keychain();

console.log("Initializing a toy password store");
keychain.init(password);

var kvs = { "service1": "value1", 
            "service2": "value2",
            "service3": "value3" };

console.log("Adding keys to password manager");
for (var k in kvs) {
  keychain.set(k, kvs[k]);
}

console.log("Testing get");
for (var k in kvs) {
  assert(keychain.get(k) === kvs[k], "Get failed for key " + k);
}
assert(keychain.get("service4") === null);

console.log("Testing remove");
assert(keychain.remove("service1"));
assert(!keychain.remove("service4"));
assert(keychain.get("service4") === null);

console.log("Saving database");
var data = keychain.dump();

var contents = data[0];
var cksum = data[1];

console.log("Loading database");
var new_keychain = password_manager.keychain();
new_keychain.load(password, contents, cksum);

console.log("Checking contents of new database");
for (var k in kvs) {
  assert(keychain.get(k) === new_keychain.get(k));
}

var setup = function(keychain){
    keychain.init(password)
    for (var k in kvs) {
      keychain.set(k, kvs[k]);
    }
}

// swap attack
setup(keychain)
var data = keychain.dump()[0]
var map = JSON.parse(data)
var keys = []
for (var k in map) keys.push(k)
var key0 = keys[0]
var key1 = keys[1]
var temp = map[key0]
map[key0] = map[key1]
map[key1] = temp
data = JSON.stringify(map)
keychain.load(password, data)

var swap_detected = 0
for (var service in kvs) {
    try {
        password = keychain.get(service)
    }
    catch(err) {
        swap_detected ++
    }
}
assert(swap_detected == 2)
console.log("Swap attacks defended!!");

// wrong password
setup(keychain)
var data = keychain.dump()[0]
assert(!keychain.load('OBAMA', data))
var error_count = 0
try {
    keychain.set("www.google.com", "123456")
} catch(err) {
    error_count ++
}
try {
    keychain.get("www.google.com")
} catch(err) {
    error_count ++
}
try {
    keychain.remove("www.google.com")
} catch(err) {
    error_count ++
}
assert(error_count == 3)
assert(keychain.dump() == null)
console.log("Data did not expose under wrong password.")

// modifying data other than kvs
setup(keychain)
var data = keychain.dump()[0]
var map = JSON.parse(data)
map["salt"] = random_bitarray(128)
data = JSON.stringify(map)
assert(!keychain.load(password, data))

setup(keychain)
var data = keychain.dump()[0]
var map = JSON.parse(data)
map["salt"] = random_bitarray(64)
data = JSON.stringify(map)
assert(!keychain.load(password, data))

setup(keychain)
var data = keychain.dump()[0]
var map = JSON.parse(data)
map["auth_message"] = random_bitarray(128)
data = JSON.stringify(map)
assert(!keychain.load(password, data))
console.log("Changing accessory data will disable the password manager!")

// roll back attack
keychain.EXTRA_CREDIT = false
setup(keychain)
var data_old = keychain.dump()
keychain.set("service1", "apple")
var data_new = keychain.dump()
var invalid = false
try {
    keychain.load(password, data_old[0], data_new[1])
} catch (err) {
    invalid = true
}
assert(invalid)
console.log("Roll back attact defended!!")

console.log("All tests passed!");
