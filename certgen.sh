#!/bin/bash
#--------------------------------------------------#
# Global Variables
#--------------------------------------------------#
CA_DIR=CA/root
INTER_CA_DIR=CA/intermediate
LOG_DIR="logs"
mismatching="mismatching-certs"
CA_CONF_PATH="config-test-cases/CA"
LEAF_CONF_PATH="config-test-cases/LEAF"
LOG_FILE="$LOG_DIR/cert-gen-logs-$(date '+%Y%m%d%H%M%S').log"
#--------------------------------------------------#
#                FUNCTIONS SECTION
#--------------------------------------------------#
# Check if OpenSSL is installed
check_openssl() {
  if command -v openssl > /dev/null; then
    echo "OpenSSL is installed"
    openssl version
  else
    echo "OpenSSL is not installed. Please install OpenSSL and run the script again."
    exit 1
  fi
}
# Function to help us with the formatting for better readability
format() {
  if [ "$1" = "test-header" ]; then
    echo -e "==================================================================================================================================================="
  else
    echo -e "---------------------------------------------------------------------------------------------------------------------------------------------------"
  fi
}
# Check password provided
password_cli_parameter_required() {
  if [ -z "$PASSWORD" ]; then
    echo "A password for the certificates was not specified. Please define a password using -p or --password option."
    echo "Example : certgen.sh -p verystrongpwd"
    exit 3
  fi
}
# Function to create folder structure for the generated certs
create_folders() {
    echo "Creating folder structure for the generated certificates..."
    mkdir -p "CA/root" || { echo "Failed to create CA/root directory."; exit 4; }
    mkdir -p "CA/intermediate/newcerts" || { echo "Failed to create CA/intermediat/newcerts directory."; exit 5; }
    mkdir -p "DSA" || { echo "Failed to create DSA directory."; exit 6; }
    mkdir -p "RSA" || { echo "Failed to create RSA directory."; exit 7; }
    mkdir -p "ECDSA" || { echo "Failed to create ECDSA directory."; exit 8; }
    mkdir -p "ED25519" || { echo "Failed to create ED25519 directory."; exit 9; }
    mkdir -p "logs" || { echo "Failed to create logs directory."; exit 10; }
    mkdir -p "mismatching-certs" || { echo "Failed to create mismatching-certs directory."; exit 11; }
    echo "Folders created successfully."
}
# Function to generate private keys
generate_private_key() {
    local key_algorithm=$1
    local key_out=$2
    local config_file=$3
    local curve_name=$4
    local key_size

    key_size=$(awk -F" *= *" '/default_bits/ {print $2}' "$config_file")

    if [ -z "$key_size" ]; then
        key_size=2048
    fi

    echo "Generating $key_algorithm private key on $key_out with key size $key_size bits..."
    case "$key_algorithm" in
        "RSA")
            openssl genpkey -algorithm RSA -out "$key_out" -aes256 -pass pass:"$PASSWORD" -pkeyopt rsa_keygen_bits:"$key_size" || { echo "Failed to generate RSA private key."; exit 12; }
            ;;
        "DSA")
            local dsaparam_out="$CA_DIR/dsaparam.pem"
            openssl dsaparam -out "$dsaparam_out" "$key_size" || { echo "Failed to generate DSA parameters."; exit 13; }
            openssl gendsa -out "$key_out" -passout pass:"$PASSWORD" "$dsaparam_out" || { echo "Failed to generate DSA private key."; exit 14; }
            ;;
        "ECDSA")
            if [ -z "$curve_name" ]; then
                curve_name="prime256v1"
            fi
            openssl ecparam -name "$curve_name" -genkey -out "$key_out" || { echo "Failed to generate ECDSA private key."; exit 15; }
            ;;
        "ED25519")
            openssl genpkey -algorithm ED25519 -out "$key_out" || { echo "Failed to generate ED25519 private key."; exit 16; }
            ;;
        *)
            echo "Unknown key algorithm: $key_algorithm"
            return 1
            ;;
    esac
}
# Function to generate CA certificates
generate_ca_certificate() {
    local config_file=$1
    local key_algorithm=$2
    local days=$3
    local test_case_number=$4
    local curve_name=$5
    local ca_name
    ca_name=$(basename "$config_file" .cnf)
    local key_out="$CA_DIR/${test_case_number}_${ca_name}_${key_algorithm}_priv.key"
    local cert_out="$CA_DIR/${test_case_number}_${ca_name}_${key_algorithm}_pub.pem"
    # Validate required parameters (days and curve_name is not required)
    for param in "config_file" "key_algorithm" "test_case_number"; do
        if [ -z "${!param}" ]; then
            echo "Error: Missing required parameter '$param'."
            exit 1
        fi
    done
    echo "Generating $key_algorithm CA certificate on $cert_out."
    generate_private_key "$key_algorithm" "$key_out" "$config_file" "$curve_name" || { echo "Failed to generate $key_algorithm private key."; exit 17; }
    echo "Generating CA root certificate with openssl req -config $config_file -key $key_out -passin pass:$PASSWORD -new -x509 -days ${days:-3650} -out $cert_out"
    if ! openssl req -config "$config_file" -key "$key_out" -passin pass:"$PASSWORD" -new -x509 -days "${days:-3650}" -out "$cert_out"; then
      echo "Failed to generate $key_algorithm CA certificate."
      exit 18
    fi
    format
    echo "Verifying generated $key_algorithm root CA $ca_name"
    format
    if ! openssl crl2pkcs7 -nocrl -certfile "$cert_out" | openssl pkcs7 -print_certs -text -noout | grep -Ev '^[ \t]*[0-9A-Fa-f:]{2,}$'; then
      echo "Failed to verify $key_algorithm $ca_name."
      exit 19
    fi
}
# Function to generate intermediate CA certificates
generate_intermediate_certificate() {
    local inter_config=$1
    local key_algorithm=$2
    local days=$3
    local root_ca_cert=$4
    local root_ca_key=$5
    local test_case_number=$6
    local curve_name=$7
    local inter_ca_name
    inter_ca_name=$(basename "$inter_config" .cnf)
    local key_out="$INTER_CA_DIR/${test_case_number}_${inter_ca_name}_${key_algorithm}_priv.key"
    local csr_out="$INTER_CA_DIR/${test_case_number}_${inter_ca_name}_${key_algorithm}.csr"
    local cert_out="$INTER_CA_DIR/${test_case_number}_${inter_ca_name}_${key_algorithm}_pub.pem"
    # Validate required parameters (days and curve_name is not required)
    for param in "inter_config" "key_algorithm" "root_ca_cert" "root_ca_key" "test_case_number"; do
        if [ -z "${!param}" ]; then
            echo "Error: Missing required parameter '$param'."
            exit 20
        fi
    done
    # Make sure index.txt is created and it's clean.
    rm "$INTER_CA_DIR/index.txt"
    touch "$INTER_CA_DIR/index.txt"

    echo "Generating $key_algorithm intermediate CA certificate on $cert_out...."
    generate_private_key "$key_algorithm" "$key_out" "$inter_config" "$curve_name"  || { echo "Failed to generate $key_algorithm private key."; exit 21; }
    echo "Generating intermediate CA CSR with openssl req -config $inter_config -key $key_out -passin pass:$PASSWORD -new -out $csr_out"
    if ! openssl req -config "$inter_config" -key "$key_out" -passin pass:"$PASSWORD" -new -out "$csr_out"; then
      echo "Failed to generate CSR."
      exit 20
    fi
    echo "Generating intermediate CA CSR with openssl ca -config $inter_config -in $csr_out -out $cert_out -batch -notext -days ${days:-3650} -cert $root_ca_cert -keyfile $root_ca_key -passin pass:$PASSWORD "
    if ! openssl ca -config "$inter_config" -in "$csr_out" -out "$cert_out" -batch -notext -days "${days:-3650}" -cert "$root_ca_cert" -keyfile "$root_ca_key" -passin pass:"$PASSWORD"; then
        echo "Failed to generate intermediate CA certificate."
        exit 21
    fi
    # if ! openssl x509 -req -extfile "$inter_config" -in "$csr_out" -CA "$root_ca_cert" -CAkey "$root_ca_key" -passin pass:"$PASSWORD" -CAcreateserial -out "$cert_out" -days "${days:-3650}"; then
    #   echo "Failed to generate intermediate CA certificate."
    #   exit 21
    # fi
    format
    echo "Verifying generated $key_algorithm intermediate CA $inter_ca_name."
    format
    if ! openssl crl2pkcs7 -nocrl -certfile "$cert_out" | openssl pkcs7 -print_certs -text -noout | grep -Ev '^[ \t]*[0-9A-Fa-f:]{2,}$'; then
      echo "Failed to verify $key_algorithm $inter_ca_name."
      exit 22
    fi
}
# Function to generate leaf certificates
gen_leaf_cert() {
    local leaf_config="$1"
    local ca_cert="$2"
    local ca_key="$3"
    local inter_cert="$4"
    local inter_key="$5"
    local key_algorithm="$6"
    local validity_period="$7"
    local bundle_type="$8"
    local test_case_number="$9"
    local curve_name="${10}"
    local leaf_dir="$key_algorithm"
    local key_out="$leaf_dir/${test_case_number}_${key_algorithm}_priv.pem"
    local cert_out="$leaf_dir/${test_case_number}_${key_algorithm}_pub.pem"
    local csr_out="$leaf_dir/${test_case_number}_${key_algorithm}.csr"
    local pem_file="$leaf_dir/${test_case_number}_${key_algorithm}_bundle.pem"
    local der_file="$leaf_dir/${test_case_number}_${key_algorithm}_pub.der"
    local p12_file="$leaf_dir/${test_case_number}_${key_algorithm}_bundle.p12"
    local ca_chain_file="$leaf_dir/${test_case_number}_${key_algorithm}_ca_chain.pem"

    # Validate required parameters
    for param in leaf_config ca_cert ca_key key_algorithm validity_period bundle_type test_case_number; do
        if [ -z "${!param}" ]; then
            echo "Error: Missing required parameter '$param'."
            return 1
        fi
    done

    # Validate optional parameters
    if [ "$bundle_type" = "pub_priv_root_inter" ]; then
        if [ -z "$inter_cert" ] || [ -z "$inter_key" ]; then
            echo "Error: Missing intermediate CA certificate or key for bundle type 'pub_priv_root_inter'."
            return 1
        fi
    fi

    generate_private_key "$key_algorithm" "$key_out" "$leaf_config" "$curve_name" || return 1
    echo "generating CSR with openssl req -new -key $key_out -out $csr_out -config $leaf_config -passin pass:$PASSWORD"
    openssl req -new -key "$key_out" -out "$csr_out" -config "$leaf_config" -passin pass:"$PASSWORD" || { echo "Failed to generate CSR."; exit 23; }

    local signing_cert="$ca_cert"
    local signing_key="$ca_key"
    if [ "$bundle_type" = "pub_priv_root_inter" ]; then
        signing_cert="$inter_cert"
        signing_key="$inter_key"
    fi
    
    echo "Generating LEAF cert with : openssl req -in $csr_out -out $cert_out -CA $signing_cert -CAkey $signing_key -days $validity_period -config $leaf_config -passin pass:$PASSWORD -x509 -copy_extensions copy"
    openssl req -in "$csr_out" -out "$cert_out" -CA "$signing_cert" -CAkey "$signing_key" -days "$validity_period" -config "$leaf_config" -passin pass:"$PASSWORD" -x509 -copy_extensions copy || { echo "Failed to generate leaf certificate."; exit 24; }

    # Concatenate the appropriate certificates to create the full bundle in PEM format
    case "$bundle_type" in
        "pub")
            cat "$cert_out" > "$pem_file"
            ;;
        "pub_priv")
            cat "$cert_out" "$key_out" > "$pem_file"
            ;;
        "pub_priv_root")
            cat "$cert_out" "$key_out" "$ca_cert" > "$pem_file"
            ;;
        "pub_priv_root_inter")
            cat "$cert_out" "$key_out" "$ca_cert" "$inter_cert" > "$pem_file"
            cat "$inter_cert" "$ca_cert" > "$ca_chain_file"
            ;;
        *)
            echo "Unknown bundle type: $bundle_type"
            return 1
            ;;
    esac

    # Convert PEM to DER format for public certificate
    openssl x509 -inform PEM -outform DER -in "$cert_out" -out "$der_file" || { echo "Failed to convert certificate to DER format."; exit 25; }

    # Export to PKCS#12 format, include the full chain if bundle type allows
    if [ "$bundle_type" = "pub_priv_root_inter" ]; then
        openssl pkcs12 -export -out "$p12_file" -inkey "$key_out" -in "$cert_out" -certfile "$ca_chain_file" -passin pass:"$PASSWORD" -passout pass:"$PASSWORD" || { echo "Failed to create PKCS#12 bundle."; exit 26; }
        cp "$p12_file" "${p12_file%.p12}.pfx"
    elif [ "$bundle_type" = "pub_priv_root" ]; then
        openssl pkcs12 -export -out "$p12_file" -inkey "$key_out" -in "$cert_out" -CAfile "$ca_cert" -passin pass:"$PASSWORD" -passout pass:"$PASSWORD" || { echo "Failed to create PKCS#12 bundle."; exit 27; }
        cp "$p12_file" "${p12_file%.p12}.pfx"
    elif [ "$bundle_type" = "pub_priv" ]; then
        openssl pkcs12 -export -out "$p12_file" -inkey "$key_out" -in "$cert_out" -passin pass:"$PASSWORD" -passout pass:"$PASSWORD" || { echo "Failed to create PKCS#12 bundle."; exit 28; }
        cp "$p12_file" "${p12_file%.p12}.pfx"
    elif [ "$bundle_type" = "pub" ]; then
        # This case handles creating a PKCS#12 file with only the public certificate.
        # Note: This is non-standard and may not work as expected in all contexts, included as a corner case.
        openssl pkcs12 -export -out "$p12_file" -nokeys -in "$cert_out" -passout pass:"$PASSWORD" || { echo "Failed to create public only PKCS#12 file."; exit 29; }
    fi

    # Output the text of the generated cert
    format
    echo "Below the LEAF PEM bundle visualized without the hex data for $pem_file"
    format
    openssl crl2pkcs7 -nocrl -certfile "$pem_file" | openssl pkcs7 -print_certs -text -noout | grep -Ev '^[ \t]*[0-9A-Fa-f:]{2,}$'

    # Verification for PKCS#12 file
    format
    echo "Verifying PKCS#12 $p12_file file..."
    format
    if ! openssl pkcs12 -info -in "$p12_file" -passin pass:"$PASSWORD" -noout; then
        echo "Verification failed for PKCS#12 file."
        return 25
    else
        echo "PKCS#12 file is verified."
    fi

    echo "Generated leaf certificate and bundle with type $bundle_type."
}
# Function to generate CA, intermediate, and leaf certificates with mismatching keys for the leaf certificates
generate_mismatching_certs() {
  # Generate CA A key and certificate
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$mismatching/CA_A_key.pem"
  openssl req -x509 -new -nodes -key "$mismatching/CA_A_key.pem" -sha256 -days 1024 -out "$mismatching/CA_A_cert.pem" -subj "/CN=CA_A"

  # Generate CA B key and certificate
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$mismatching/CA_B_key.pem"
  openssl req -x509 -new -nodes -key "$mismatching/CA_B_key.pem" -sha256 -days 1024 -out "$mismatching/CA_B_cert.pem" -subj "/CN=CA_B"

  # Generate Intermediate A key and certificate signed by CA A
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$mismatching/Intermediate_A_key.pem"
  openssl req -new -key "$mismatching/Intermediate_A_key.pem" -out "$mismatching/Intermediate_A.csr" -subj "/CN=Intermediate_A"
  openssl x509 -req -in "$mismatching/Intermediate_A.csr" -CA "$mismatching/CA_A_cert.pem" -CAkey "$mismatching/CA_A_key.pem" -CAcreateserial -out "$mismatching/Intermediate_A_cert.pem" -days 500 -sha256

  # Generate Intermediate B key and certificate signed by CA B
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$mismatching/Intermediate_B_key.pem"
  openssl req -new -key "$mismatching/Intermediate_B_key.pem" -out "$mismatching/Intermediate_B.csr" -subj "/CN=Intermediate_B"
  openssl x509 -req -in "$mismatching/Intermediate_B.csr" -CA "$mismatching/CA_B_cert.pem" -CAkey "$mismatching/CA_B_key.pem" -CAcreateserial -out "$mismatching/Intermediate_B_cert.pem" -days 500 -sha256

  # Generate Leaf A key
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$mismatching/Leaf_A_key.pem"

  # Generate Leaf B key (This will be used to create a mismatch)
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$mismatching/Leaf_B_key.pem"

  # Generate Leaf A certificate signing request (CSR) using Leaf A key
  openssl req -new -key "$mismatching/Leaf_A_key.pem" -out "$mismatching/Leaf_A.csr" -subj "/CN=Leaf_A"

  # Generate Leaf B certificate signing request (CSR) using Leaf A key
  openssl req -new -key "$mismatching/Leaf_B_key.pem" -out "$mismatching/Leaf_B.csr" -subj "/CN=Leaf_B"

  # Sign the Leaf A CSR with the Intermediate A certificate (This will create a matching pair, which we'll then break)
  openssl x509 -req -in "$mismatching/Leaf_A.csr" -CA "$mismatching/Intermediate_A_cert.pem" -CAkey "$mismatching/Intermediate_A_key.pem" -CAcreateserial -out "$mismatching/Leaf_A_cert.pem" -days 365 -sha256

  # Now, sign the Leaf A CSR with the Intermediate B certificate to create a matching Leaf B certificate
  openssl x509 -req -in "$mismatching/Leaf_B.csr" -CA "$mismatching/Intermediate_B_cert.pem" -CAkey "$mismatching/Intermediate_B_key.pem" -CAcreateserial -out "$mismatching/Leaf_B_cert.pem" -days 365 -sha256

  # Create a mismatching bundle for Leaf A (Leaf A + Intermediate A + CA A public + CA B private)
  cat "$mismatching/Leaf_A_cert.pem" "$mismatching/Intermediate_A_cert.pem" "$mismatching/CA_A_cert.pem" "$mismatching/CA_B_key.pem" > "$mismatching/Leaf_A_wrong_CA_priv_key_bundle.pem"

  # Create certificate bundle for Leaf B (Leaf B + Intermediate B + CA B)
  cat "$mismatching/Leaf_B_cert.pem" "$mismatching/Leaf_A_key.pem" "$mismatching/Intermediate_B_cert.pem" "$mismatching/CA_B_cert.pem" > "$mismatching/Leaf_B_wrong_leaf_priv_key_bundle.pem"

  # Create CA key mismatch and Leaf cert mismatch
  cat "$mismatching/Leaf_A_cert.pem"  "$mismatching/CA_B_key.pem" > "$mismatching/CA-mismatch.pem"


  # Clean up CSR files
  if [ -n "$mismatching" ]; then
    rm $mismatching/*.csr
    rm $mismatching/*.srl
  fi

}

# Increment serial number for certificate issuance
increment_serial() {
  current_serial=$(cat "$INTER_CA_DIR/serial")
  next_serial=$(printf '%d' "$((current_serial + 1))")
  echo "$next_serial" > "$INTER_CA_DIR/serial"
}

# Gen test cases (main function that calls other functions)
gen_ca_test_cases() {
  local test_desc="$1"
  local ca_config="$2"
  local inter_config="$3"
  local key_algorithm="$4"
  local validity_period="$5"
  local test_case_number="$6"
  local curve_name="$7"
  local leaf_config="$8"
  local bundle_type="$9"

  format test-header
  echo "$test_desc"
  format test-header
  local ca_cert
  ca_cert="$CA_DIR/${test_case_number}_$(basename "$ca_config" .cnf)_${key_algorithm}_pub.pem"
  local ca_key
  ca_key="$CA_DIR/${test_case_number}_$(basename "$ca_config" .cnf)_${key_algorithm}_priv.key"

  generate_ca_certificate "$ca_config" "$key_algorithm" "$validity_period" "$test_case_number" "$curve_name"

  # Ensure serial exists and has a default value for the intermediate CA
  if [ ! -f "$INTER_CA_DIR/serial" ]; then
    echo '1000' > "$INTER_CA_DIR/serial"
  fi

  local inter_cert=""
  local inter_key=""
  if [ -n "$inter_config" ]; then
    inter_cert="$INTER_CA_DIR/${test_case_number}_$(basename "$inter_config" .cnf)_${key_algorithm}_pub.pem"
    inter_key="$INTER_CA_DIR/${test_case_number}_$(basename "$inter_config" .cnf)_${key_algorithm}_priv.key"

    if generate_intermediate_certificate "$inter_config" "$key_algorithm" "$validity_period" "$ca_cert" "$ca_key" "$test_case_number" "$curve_name"; then
      increment_serial # Increment the serial after a successful certificate generation
    fi
  fi

  if [ -n "$leaf_config" ]; then
    gen_leaf_cert "$leaf_config" "$ca_cert" "$ca_key" "$inter_cert" "$inter_key" "$key_algorithm" "$validity_period" "$bundle_type" "$test_case_number" "$curve_name"
  fi
}

#-------------------------------------------------------------------#
#    ACTUAL SCRIPT EXECUTION / CA and Intermediate CA TEST CASES
#-------------------------------------------------------------------#
# CLI argument to specify password
while [[ "$#" -gt 0 ]]; do
  case $1 in
    -p|--password) PASSWORD="$2"; shift ;;
    *) echo "Unknown parameter passed: $1"; exit 1 ;;
  esac
  shift
done
password_cli_parameter_required
check_openssl
create_folders
generate_mismatching_certs
gen_ca_test_cases "Test case 001: Generating RSA root and intermediate CA using 00-default-CA.cnf and 001-interm-CA.cnf" \
    "$CA_CONF_PATH/00-default-CA.cnf" "$CA_CONF_PATH/001-interm-CA.cnf" \
    "RSA" "" "001" 2>&1 | tee -a "$LOG_FILE"

gen_ca_test_cases "Test case 002: Generating DSA root and intermediate CA using 00-default-CA.cnf and 001-interm-CA.cnf" \
    "$CA_CONF_PATH/00-default-CA.cnf" "$CA_CONF_PATH/001-interm-CA.cnf" \
    "DSA" "" "002" 2>&1 | tee -a "$LOG_FILE"

gen_ca_test_cases "Test case 003: Generating ECDSA root and intermediate CA using 00-default-CA.cnf and 001-interm-CA.cnf" \
    "$CA_CONF_PATH/00-default-CA.cnf" "$CA_CONF_PATH/001-interm-CA.cnf" \
    "ECDSA" "" "003" 2>&1 | tee -a "$LOG_FILE"

gen_ca_test_cases "Test case 004: Generating ED25519 root and intermediate CA using 00-default-CA.cnf and 001-interm-CA.cnf" \
    "$CA_CONF_PATH/00-default-CA.cnf" "$CA_CONF_PATH/001-interm-CA.cnf" \
    "ED25519" "" "004" 2>&1 | tee -a "$LOG_FILE"

gen_ca_test_cases "Test case 005: Generating RSA root CA using 02-CA-false.cnf with CA:false" \
    "$CA_CONF_PATH/02-CA-false.cnf" "" \
    "RSA" "" "005" 2>&1 | tee -a "$LOG_FILE"

gen_ca_test_cases "Test case 006: Generating ECDSA root CA using 02-CA-false.cnf with CA:false" \
    "$CA_CONF_PATH/02-CA-false.cnf" "" \
    "ECDSA" "" "006" 2>&1 | tee -a "$LOG_FILE"

gen_ca_test_cases "Test case 007: Generating RSA root CA using 03-CA-1024-bit.cnf" \
    "$CA_CONF_PATH/03-CA-1024-bit.cnf" "" \
    "RSA" "" "007" 2>&1 | tee -a "$LOG_FILE"

gen_ca_test_cases "Test case 008: Generating DSA root CA using 03-CA-1024-bit.cnf" \
    "$CA_CONF_PATH/03-CA-1024-bit.cnf" "" \
    "DSA" "" "008" 2>&1 | tee -a "$LOG_FILE"

gen_ca_test_cases "Test case 009: Generating RSA root CA using 04-CA-md5.cnf with md5" \
    "$CA_CONF_PATH/04-CA-md5.cnf" "" \
    "RSA" "" "009" 2>&1 | tee -a "$LOG_FILE"

gen_ca_test_cases "Test case 010: Generating ECDSA root CA using 05-CA-sha1.cnf" \
    "$CA_CONF_PATH/05-CA-sha1.cnf" "" \
    "ECDSA" "" "010" 2>&1 | tee -a "$LOG_FILE"

gen_ca_test_cases "Test case 011: Generating ECDSA root CA 1-day validity using 00-default-CA.cnf" \
    "$CA_CONF_PATH/00-default-CA.cnf" \
    ""  "ECDSA" "1" "011" 2>&1 | tee -a "$LOG_FILE"

gen_ca_test_cases "Test case 012: Generating RSA root CA 1-day validity using 00-default-CA.cnf" \
    "$CA_CONF_PATH/00-default-CA.cnf" \
    ""  "RSA" "1" "012" 2>&1 | tee -a "$LOG_FILE"

gen_ca_test_cases "Test case 013: Generating ED25519 root/intermediate CA 1-day validity using 00-default-CA.cnf" \
    "$CA_CONF_PATH/00-default-CA.cnf" "$CA_CONF_PATH/001-interm-CA.cnf" \
    "ED25519" "1" "013" 2>&1 | tee -a "$LOG_FILE"

gen_ca_test_cases "Test case 014: Generating ECDSA root CA (busy extensions) 30-days validity using 06-CA-combined.cnf" \
    "$CA_CONF_PATH/06-CA-combined.cnf" "" \
    "RSA" "30" "014" 2>&1 | tee -a "$LOG_FILE"

gen_ca_test_cases "Test case 015: Generating RSA root CA (busy extensions) 90-days validity using 06-CA-combined.cnf" \
    "$CA_CONF_PATH/06-CA-combined.cnf" "" \
    "ECDSA" "90" "015" 2>&1 | tee -a "$LOG_FILE"

gen_ca_test_cases "Test case 016: Generating RSA root CA using 07-CA-512-bit.cnf" \
    "$CA_CONF_PATH/07-CA-512-bit.cnf" "" \
    "RSA" "" "016" 2>&1 | tee -a "$LOG_FILE"

gen_ca_test_cases "Test case 017: Generating RSA root CA using 08-CA-4096-bit.cnf" \
    "$CA_CONF_PATH/08-CA-4096-bit.cnf" "" \
    "RSA" "" "017" 2>&1 | tee -a "$LOG_FILE"

gen_ca_test_cases "Test case 018: Generating RSA root CA using 09-CA-8192-bit.cnf" \
    "$CA_CONF_PATH/09-CA-8192-bit.cnf" "" \
    "RSA" "" "018" 2>&1 | tee -a "$LOG_FILE"

gen_ca_test_cases "Test case 019: Generating ECDSA root CA using 10-CA-sha384.cnf" \
    "$CA_CONF_PATH/10-CA-sha384.cnf" "" \
    "ECDSA" "" "019" 2>&1 | tee -a "$LOG_FILE"

gen_ca_test_cases "Test case 020: Generating ECDSA root CA using 11-CA-sha512.cnf" \
    "$CA_CONF_PATH/11-CA-sha512.cnf" "" \
    "ECDSA" "" "020" 2>&1 | tee -a "$LOG_FILE"

gen_ca_test_cases "Test case 021: Generating RSA root CA using 12-CA-sha3-256.cnf" \
    "$CA_CONF_PATH/12-CA-sha3-256.cnf" "" \
    "RSA" "" "021" 2>&1 | tee -a "$LOG_FILE"

gen_ca_test_cases "Test case 022: Generating ECDSA root CA using 12-CA-sha3-256.cnf" \
    "$CA_CONF_PATH/12-CA-sha3-256.cnf" "" \
    "ECDSA" "" "022" 2>&1 | tee -a "$LOG_FILE"

gen_ca_test_cases "Test case 023: Generating ECDSA root CA using 13-CA-sha3-384.cnf" \
    "$CA_CONF_PATH/13-CA-sha3-384.cnf" "" \
    "ECDSA" "" "023" 2>&1 | tee -a "$LOG_FILE"

gen_ca_test_cases "Test case 024: Generating ECDSA root CA using 14-CA-sha3-512.cnf" \
    "$CA_CONF_PATH/14-CA-sha3-512.cnf" "" \
    "ECDSA" "" "024" 2>&1 | tee -a "$LOG_FILE"

gen_ca_test_cases "Test case 025: Generating RSA root CA using 15-CA-special-chars.cnf" \
    "$CA_CONF_PATH/15-CA-special-chars.cnf" "" \
    "RSA" "" "025" 2>&1 | tee -a "$LOG_FILE"

gen_ca_test_cases "Test case 026: Generating RSA root CA using 16-CA-binary.cnf" \
    "$CA_CONF_PATH/16-CA-binary.cnf" "" \
    "RSA" "" "026" 2>&1 | tee -a "$LOG_FILE"

gen_ca_test_cases "Test case 027: Generating ECDSA root CA using 17-CA-latin-chars.cnf" \
    "$CA_CONF_PATH/17-CA-latin-chars.cnf" "" \
    "ECDSA" "" "027" 2>&1 | tee -a "$LOG_FILE"

gen_ca_test_cases "Test case 028: Generating RSA root CA using 18-CA-command-injection.cnf" \
    "$CA_CONF_PATH/18-CA-command-injection.cnf" "" \
    "ECDSA" "" "028" 2>&1 | tee -a "$LOG_FILE"

gen_ca_test_cases "Test case 029: Generating ECDSA secp384r1 root and intermediate CA using 00-default-CA.cnf and 001-interm-CA.cnf" \
    "$CA_CONF_PATH/00-default-CA.cnf" "$CA_CONF_PATH/001-interm-CA.cnf" \
    "ECDSA" "" "029" "secp384r1" 2>&1 | tee -a "$LOG_FILE"

gen_ca_test_cases "Test case 030: Generating ECDSA secp521r1 root CA using 00-default-CA.cnf" \
    "$CA_CONF_PATH/00-default-CA.cnf" "" \
    "ECDSA" "" "030" "secp521r1" 2>&1 | tee -a "$LOG_FILE"

gen_ca_test_cases "Test case 031: Generating ECDSA sect571r1 root CA using 14-CA-sha3-512.cnf" \
    "$CA_CONF_PATH/14-CA-sha3-512.cnf" "" \
    "ECDSA" "" "031" "sect571r1" 2>&1 | tee -a "$LOG_FILE"

gen_ca_test_cases "Test case 032: Generating ECDSA c2tnb431r1 root CA using 14-CA-sha3-512.cnf" \
    "$CA_CONF_PATH/14-CA-sha3-512.cnf" "" \
    "ECDSA" "" "032" "c2tnb431r1" 2>&1 | tee -a "$LOG_FILE"
# LEAF certs
gen_ca_test_cases "Test case 033: Generating RSA leaf certificate containing public and private keys in the bundle" \
    "$CA_CONF_PATH/00-default-CA.cnf" "" \
    "RSA" "365" "033" "" \
    "$LEAF_CONF_PATH/00-default-LEAF.cnf" "pub_priv" 2>&1 | tee -a "$LOG_FILE"

gen_ca_test_cases "Test case 034: Generating RSA leaf certificate containing only public key" \
    "$CA_CONF_PATH/00-default-CA.cnf" "" \
    "RSA" "365" "034" "" \
    "$LEAF_CONF_PATH/00-default-LEAF.cnf" "pub" 2>&1 | tee -a "$LOG_FILE"

gen_ca_test_cases "Test case 035: Generating RSA leaf certificate containing public plus private and CA cert" \
    "$CA_CONF_PATH/00-default-CA.cnf" "" \
    "RSA" "365" "035" "" \
    "$LEAF_CONF_PATH/00-default-LEAF.cnf" "pub_priv_root" 2>&1 | tee -a "$LOG_FILE"

gen_ca_test_cases "Test case 036: Generating RSA leaf certificate bundle containing public plus private and root / intermediate CA's" \
    "$CA_CONF_PATH/00-default-CA.cnf" "$CA_CONF_PATH/001-interm-CA.cnf" \
    "RSA" "365" "036" "" \
    "$LEAF_CONF_PATH/00-default-LEAF.cnf" "pub_priv_root_inter" 2>&1 | tee -a "$LOG_FILE"

gen_ca_test_cases "Test case 037: Generating DSA leaf certificate containing public and private keys" \
    "$CA_CONF_PATH/00-default-CA.cnf" "" \
    "DSA" "365" "037" "" \
    "$LEAF_CONF_PATH/00-default-LEAF.cnf" "pub_priv" 2>&1 | tee -a "$LOG_FILE"

gen_ca_test_cases "Test case 038: Generating DSA leaf certificate containing only public key" \
    "$CA_CONF_PATH/00-default-CA.cnf" "" \
    "DSA" "365" "038" "" \
    "$LEAF_CONF_PATH/00-default-LEAF.cnf" "pub" 2>&1 | tee -a "$LOG_FILE"

gen_ca_test_cases "Test case 039: Generating DSA leaf certificate containing public plus private and CA cert" \
    "$CA_CONF_PATH/00-default-CA.cnf" "" \
    "DSA" "365" "039" "" \
    "$LEAF_CONF_PATH/00-default-LEAF.cnf" "pub_priv_root" 2>&1 | tee -a "$LOG_FILE"

gen_ca_test_cases "Test case 040: Generating DSA leaf certificate bundle containing public plus private and root / intermediate CA's" \
    "$CA_CONF_PATH/00-default-CA.cnf" "$CA_CONF_PATH/001-interm-CA.cnf" \
    "DSA" "365" "040" "" \
    "$LEAF_CONF_PATH/00-default-LEAF.cnf" "pub_priv_root_inter" 2>&1 | tee -a "$LOG_FILE"

gen_ca_test_cases "Test case 041: Generating RSA leaf certificate containing public and private keys" \
    "$CA_CONF_PATH/00-default-CA.cnf" "" \
    "RSA" "365" "041" "" \
    "$LEAF_CONF_PATH/00-default-LEAF.cnf" "pub_priv" 2>&1 | tee -a "$LOG_FILE"

gen_ca_test_cases "Test case 042: Generating RSA leaf certificate containing only public key" \
    "$CA_CONF_PATH/00-default-CA.cnf" "" \
    "RSA" "365" "042" "" \
    "$LEAF_CONF_PATH/00-default-LEAF.cnf" "pub" 2>&1 | tee -a "$LOG_FILE"

gen_ca_test_cases "Test case 043: Generating RSA leaf certificate containing public plus private and CA cert" \
    "$CA_CONF_PATH/00-default-CA.cnf" "" \
    "RSA" "365" "043" "" \
    "$LEAF_CONF_PATH/00-default-LEAF.cnf" "pub_priv_root" 2>&1 | tee -a "$LOG_FILE"

gen_ca_test_cases "Test case 044: Generating RSA leaf certificate bundle containing public plus private and root / intermediate CA's" \
    "$CA_CONF_PATH/00-default-CA.cnf" "$CA_CONF_PATH/001-interm-CA.cnf" \
    "RSA" "365" "044" "" \
    "$LEAF_CONF_PATH/00-default-LEAF.cnf" "pub_priv_root_inter" 2>&1 | tee -a "$LOG_FILE"

gen_ca_test_cases "Test case 045: Generating ECDSA leaf certificate containing public and private keys" \
    "$CA_CONF_PATH/00-default-CA.cnf" "" \
    "ECDSA" "365" "045" "" \
    "$LEAF_CONF_PATH/00-default-LEAF.cnf" "pub_priv" 2>&1 | tee -a "$LOG_FILE"

gen_ca_test_cases "Test case 046: Generating ECDSA leaf certificate containing only public key" \
    "$CA_CONF_PATH/00-default-CA.cnf" "" \
    "ECDSA" "365" "046" "" \
    "$LEAF_CONF_PATH/00-default-LEAF.cnf" "pub" 2>&1 | tee -a "$LOG_FILE"

gen_ca_test_cases "Test case 047: Generating ECDSA leaf certificate containing public plus private and CA cert" \
    "$CA_CONF_PATH/00-default-CA.cnf" "" \
    "ECDSA" "365" "047" "" \
    "$LEAF_CONF_PATH/00-default-LEAF.cnf" "pub_priv_root" 2>&1 | tee -a "$LOG_FILE"

gen_ca_test_cases "Test case 048: Generating ECDSA leaf certificate bundle containing public plus private and root / intermediate CA's" \
    "$CA_CONF_PATH/00-default-CA.cnf" "$CA_CONF_PATH/001-interm-CA.cnf" \
    "ECDSA" "365" "048" "" \
    "$LEAF_CONF_PATH/00-default-LEAF.cnf" "pub_priv_root_inter" 2>&1 | tee -a "$LOG_FILE"

gen_ca_test_cases "Test case 049: Generating ED25519 leaf certificate containing public and private keys" \
    "$CA_CONF_PATH/00-default-CA.cnf" "" \
    "ED25519" "365" "049" "" \
    "$LEAF_CONF_PATH/00-default-LEAF.cnf" "pub_priv" 2>&1 | tee -a "$LOG_FILE"

gen_ca_test_cases "Test case 050: Generating ED25519 leaf certificate containing only public key" \
    "$CA_CONF_PATH/00-default-CA.cnf" "" \
    "ED25519" "365" "050" "" \
    "$LEAF_CONF_PATH/00-default-LEAF.cnf" "pub" 2>&1 | tee -a "$LOG_FILE"

gen_ca_test_cases "Test case 051: Generating ED25519 leaf certificate containing public plus private and CA cert" \
    "$CA_CONF_PATH/00-default-CA.cnf" "" \
    "ED25519" "365" "051" "" \
    "$LEAF_CONF_PATH/00-default-LEAF.cnf" "pub_priv_root" 2>&1 | tee -a "$LOG_FILE"

gen_ca_test_cases "Test case 052: Generating ED25519 leaf certificate bundle containing public plus private and root / intermediate CA's" \
    "$CA_CONF_PATH/00-default-CA.cnf" "$CA_CONF_PATH/001-interm-CA.cnf" \
    "ED25519" "365" "052" "" \
    "$LEAF_CONF_PATH/00-default-LEAF.cnf" "pub_priv_root_inter" 2>&1 | tee -a "$LOG_FILE"

gen_ca_test_cases "Test case 053: Generating ED25519 10 days leaf certificate containing only public key barebone config" \
    "$CA_CONF_PATH/00-default-CA.cnf" "" \
    "ED25519" "10" "053" "" \
    "$LEAF_CONF_PATH/01-bare-bone-LEAF.cnf" "pub" 2>&1 | tee -a "$LOG_FILE"

gen_ca_test_cases "Test case 054: Generating ECDSA 1 day leaf certificate containing only public key barebone config" \
    "$CA_CONF_PATH/00-default-CA.cnf" "" \
    "ECDSA" "1" "054" "" \
    "$LEAF_CONF_PATH/01-bare-bone-LEAF.cnf" "pub" 2>&1 | tee -a "$LOG_FILE"

gen_ca_test_cases "Test case 055: Generating RSA 9999 day leaf certificate containing only public key barebone config" \
    "$CA_CONF_PATH/00-default-CA.cnf" "" \
    "RSA" "9999" "055" "" \
    "$LEAF_CONF_PATH/01-bare-bone-LEAF.cnf" "pub" 2>&1 | tee -a "$LOG_FILE"

gen_ca_test_cases "Test case 056: Generating ED25519 pub+priv leaf wildcard cert" \
    "$CA_CONF_PATH/00-default-CA.cnf" "" \
    "ED25519" "356" "056" "" \
    "$LEAF_CONF_PATH/02-wildcard-LEAF.cnf" "pub_priv" 2>&1 | tee -a "$LOG_FILE"

gen_ca_test_cases "Test case 057: Generating ECDSA pub+priv leaf wildcard cert" \
    "$CA_CONF_PATH/00-default-CA.cnf" "" \
    "ECDSA" "356" "057" "" \
    "$LEAF_CONF_PATH/02-wildcard-LEAF.cnf" "pub_priv" 2>&1 | tee -a "$LOG_FILE"

gen_ca_test_cases "Test case 058: Generating RSA pub+priv leaf wildcard cert" \
    "$CA_CONF_PATH/00-default-CA.cnf" "" \
    "RSA" "356" "058" "" \
    "$LEAF_CONF_PATH/02-wildcard-LEAF.cnf" "pub_priv" 2>&1 | tee -a "$LOG_FILE"

# Leaf certs with different bit sizes
gen_ca_test_cases "Test case 059: Generating RSA pub+priv leaf 512 bit cert" \
    "$CA_CONF_PATH/00-default-CA.cnf" "" \
    "RSA" "356" "059" "" \
    "$LEAF_CONF_PATH/03-512-bit-LEAF.cnf" "pub_priv" 2>&1 | tee -a "$LOG_FILE"

gen_ca_test_cases "Test case 060: Generating RSA pub+priv leaf 1024 bit cert" \
    "$CA_CONF_PATH/00-default-CA.cnf" "" \
    "RSA" "356" "060" "" \
    "$LEAF_CONF_PATH/04-1024-bit-LEAF.cnf" "pub_priv" 2>&1 | tee -a "$LOG_FILE"

gen_ca_test_cases "Test case 061: Generating RSA pub+priv leaf 4096 bit cert" \
    "$CA_CONF_PATH/00-default-CA.cnf" "" \
    "RSA" "356" "061" "" \
    "$LEAF_CONF_PATH/05-4096-bit-LEAF.cnf" "pub_priv" 2>&1 | tee -a "$LOG_FILE"

gen_ca_test_cases "Test case 062: Generating RSA pub+priv leaf 8192 bit cert" \
    "$CA_CONF_PATH/00-default-CA.cnf" "" \
    "RSA" "356" "062" "" \
    "$LEAF_CONF_PATH/06-8192-bit-LEAF.cnf" "pub_priv" 2>&1 | tee -a "$LOG_FILE"

gen_ca_test_cases "Test case 063: Generating RSA pub+priv leaf 9999 bit cert" \
    "$CA_CONF_PATH/00-default-CA.cnf" "" \
    "RSA" "356" "063" "" \
    "$LEAF_CONF_PATH/07-9999-bit-LEAF.cnf" "pub_priv" 2>&1 | tee -a "$LOG_FILE"

# Test cases for different leaf hashes in certs.
gen_ca_test_cases "Test case 064: Generating RSA pub+priv+root leaf md5 cert" \
    "$CA_CONF_PATH/04-CA-md5.cnf" "" \
    "RSA" "356" "064" "" \
    "$LEAF_CONF_PATH/08-md5-LEAF.cnf" "pub_priv_root" 2>&1 | tee -a "$LOG_FILE"

gen_ca_test_cases "Test case 065: Generating ECDSA pub+priv+root leaf sha1 cert" \
    "$CA_CONF_PATH/05-CA-sha1.cnf" "" \
    "ECDSA" "356" "065" "" \
    "$LEAF_CONF_PATH/09-sha1-LEAF.cnf" "pub_priv_root" 2>&1 | tee -a "$LOG_FILE"

gen_ca_test_cases "Test case 066: Generating ED25519 pub+priv+root leaf sha384 cert" \
    "$CA_CONF_PATH/10-CA-sha384.cnf" "" \
    "ED25519" "356" "066" "" \
    "$LEAF_CONF_PATH/09-sha384-LEAF.cnf" "pub_priv_root" 2>&1 | tee -a "$LOG_FILE"

gen_ca_test_cases "Test case 067: Generating ECDSA pub+priv+root+intermediate leaf sha512 cert" \
    "$CA_CONF_PATH/11-CA-sha512.cnf" "$CA_CONF_PATH/22-interm-sha512.cnf" \
    "ECDSA" "356" "067" "" \
    "$LEAF_CONF_PATH/10-sha512-LEAF.cnf" "pub_priv_root_inter" 2>&1 | tee -a "$LOG_FILE"

gen_ca_test_cases "Test case 068: Generating RSA pub+priv+root+intermediate leaf sha3-256 cert" \
    "$CA_CONF_PATH/12-CA-sha3-256.cnf" "$CA_CONF_PATH/23-interm-sha3-256.cnf" \
    "RSA" "356" "068" "" \
    "$LEAF_CONF_PATH/11-sha3-256-LEAF.cnf" "pub_priv_root_inter" 2>&1 | tee -a "$LOG_FILE"

gen_ca_test_cases "Test case 069: Generating RSA pub+priv+root+intermediate leaf sha3-384 cert" \
    "$CA_CONF_PATH/13-CA-sha3-384.cnf" "$CA_CONF_PATH/24-interm-sha3-384.cnf" \
    "RSA" "356" "069" "" \
    "$LEAF_CONF_PATH/12-sha3-384-LEAF.cnf" "pub_priv_root_inter" 2>&1 | tee -a "$LOG_FILE"

gen_ca_test_cases "Test case 070: Generating RSA pub+priv+root+intermediate leaf sha3-512 cert" \
    "$CA_CONF_PATH/14-CA-sha3-512.cnf" "$CA_CONF_PATH/070-interm-sha3-512.cnf" \
    "RSA" "356" "070" "" \
    "$LEAF_CONF_PATH/13-sha3-512-LEAF.cnf" "pub_priv_root_inter" 2>&1 | tee -a "$LOG_FILE"

# Input validation / sanitization tests
gen_ca_test_cases "Test case 071: Generating ECDSA pub+priv+root leaf special chars cert" \
    "$CA_CONF_PATH/00-default-CA.cnf" "" \
    "ECDSA" "356" "071" "" \
    "$LEAF_CONF_PATH/14-special-chars-LEAF.cnf" "pub_priv_root" 2>&1 | tee -a "$LOG_FILE"

gen_ca_test_cases "Test case 072: Generating ECDSA pub+priv+root leaf Extended Latin cert" \
    "$CA_CONF_PATH/00-default-CA.cnf" "" \
    "ECDSA" "356" "072" "" \
    "$LEAF_CONF_PATH/15-extended-latin-LEAF.cnf" "pub_priv_root" 2>&1 | tee -a "$LOG_FILE"

gen_ca_test_cases "Test case 073: Generating ED25519 pub+priv leaf cert with binary data" \
    "$CA_CONF_PATH/00-default-CA.cnf" "" \
    "ED25519" "356" "073" "" \
    "$LEAF_CONF_PATH/16-binary-LEAF.cnf" "pub_priv" 2>&1 | tee -a "$LOG_FILE"

gen_ca_test_cases "Test case 074: Generating DSA pub leaf cert with Linux x86_64 /bin/sh shellcode" \
    "$CA_CONF_PATH/00-default-CA.cnf" "" \
    "DSA" "356" "074" "" \
    "$LEAF_CONF_PATH/17-binary-shellcode-LEAF.cnf" "pub" 2>&1 | tee -a "$LOG_FILE"

gen_ca_test_cases "Test case 075: Generating DSA pub leaf cert testing command injection" \
    "$CA_CONF_PATH/00-default-CA.cnf" "" \
    "DSA" "356" "075" "" \
    "$LEAF_CONF_PATH/18-command-injection-LEAF.cnf" "pub" 2>&1 | tee -a "$LOG_FILE"

gen_ca_test_cases "Test case 076: Generating RSA bundle with extended fields" \
    "$CA_CONF_PATH/00-default-CA.cnf" "$CA_CONF_PATH/001-interm-CA.cnf" \
    "RSA" "356" "076" "" \
    "$LEAF_CONF_PATH/19-extended-LEAF.cnf" "pub_priv_root_inter" 2>&1 | tee -a "$LOG_FILE"