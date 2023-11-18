## Description 

![certgen.sh script](./certgensh.png)

#### certgen.sh is a tester's OpenSSL wrapper designed for generating and testing a wide range of certificates using a template based system and a comprehensive combinations of algorithms and ciphers (test cases, including few security ones).

## Demo
[View the Asciinema Demo](./certgen.cast)
**Tested with :**
```
OpenSSL 3.1.4 24 Oct 2023 (Library: OpenSSL 3.1.4 24 Oct 2023)
```

## Features

- **PKI dev env** you can choose to generate Root CA's, Intermediate CA's , Leaf certs in multiple combinations.
- **Choose your algorithm** , uing DSA, RSA, ECDSA or ED25519
 NOTE:DSA has been deprecated and shouldn't be used but this way we can test backends if they still accept a DSA cert, so we generate it.
- **Test case / Template based design** It uses a template , test-case friendly design where the cert can be generated accordingly with an openssl type of configuration file. see the config-test-cases/CA and config-test-cases/LEAF folders
- **Pick the signature algorithm or curve that you want**It generates certs using different signature algorithms you can define by adding test cases including md5 (do not use md5), sha1, sha256, sha384, sha512, sha3-256, sha3-394, sha3-512 and also curves for ECDSA like secp384r1, secp521r1, c2tnb431r1
- **Choose the bundle that you want** You can define the bundle of cert that you want 
  - pub (bundle containing only the pub cert)
  - pub_priv (bundle containing public plus private key)
  - pub_priv_root (bundle including the public root CA cert plus public and private certs)
  - pub_priv_root_inter (full bundle including public root and intermediate CA plus public and private key of the leaf cert)
- **Multiple cert format support** generating the certs in different cert formats : 
  - pem
  - der
  - pfx
  - p12 (pkcs#12) 
- **The generated certs are printed by default in stdout** to help you verify that what was generated was exactly what you inteded, it also displays the p12 bundles
- **opnessl ca** to generate intermediate CA certs and it includes serial number management 
- **Comprehensive preset of test cases** including security test cases like binary, binary-shellcode, command injection, also support for special chars or extended latin set of characters.
- **Error handling and logging** was implemented and it handles most of the cases but I'm not saying you won't manage to break it. As for the logging it will log to the logs/ directory.

## Usage 
```
git clone https://github.com/ArditDulemata/certgen.sh.git
cd certgen.sh
chmod +x certgen.sh
# -p is for the password, you can define your own
./certgen.sh -p mystrongpwd
```

## Adding test cases
You can add test cases by simply using the gen_ca_test_cases function, below is an explanation of each parameter

```
  local test_desc="$1"
  local ca_config="$2"
  local inter_config="$3"
  local key_algorithm="$4"
  local validity_period="$5"
  local test_case_number="$6"
  local curve_name="$7"
  local leaf_config="$8"
  local bundle_type="$9"


gen_ca_test_cases "Test case XXX: This is the name of the test case" \
    "path_to_the_root_CA_configuration_file.cnf" \
    "path_to_the_intermediate_CA_configuration_file.cnf" \
    "Algorithm (RSA OR DSA OR ECDSA OR ED25519)" \
    "certificate validity (define the expiration in days)" \
    "Number of the test case" \
    "Pick your curve for ECDSA certs" \
    "path_to_the_leaf_cert_configuration_file.cnf" \
    "Choose the bundle that you want - see features section" 2>&1 | tee -a "$LOG_FILE"
```
