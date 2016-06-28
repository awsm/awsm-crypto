: ${AWSM_CRYPTO_KEY_ID='alias/roo'}
: ${AWSM_CRYPTO_KEY_SPEC='AES_256'}
: ${AWSM_CRYPTO_OPENSSL_KEY_SPEC='aes-256-cbc'}

function echoerr() { echo -e "$@" 1>&2; }

function generate-key {
  aws kms generate-data-key \
    --key-id $AWSM_CRYPTO_KEY_ID \
    --key-spec $AWSM_CRYPTO_KEY_SPEC \
    --output json
}

function kms-encrypt {
  local plaintext=$1

  if [ -n "$plaintext" ]; then
    aws kms encrypt \
      --key-id $AWSM_CRYPTO_KEY_ID \
      --plaintext $plaintext \
      --output text \
      --query CiphertextBlob
  fi
}

function kms-decrypt {
  local ciphertext=$1

  if [ -n "$ciphertext" ]; then
    aws kms decrypt \
      --ciphertext-blob fileb://<(echo "$ciphertext" | base64 --decode) \
      --output json | jq -r ".Plaintext"
  fi
}

function encrypt {
  local input=$(cat)
  local key_data=$(generate-key)
  local key=$(echo "$key_data" | jq -r ".Plaintext")
  local encrypted_key=$(echo "$key_data" | jq -r ".CiphertextBlob")
  echoerr "= KEY $key"
  echoerr "= UNENCRYPTED MESSAGE\n"
  echoerr -e "$input"

  local data=$(openssl $AWSM_CRYPTO_OPENSSL_KEY_SPEC -k $key -base64 -e -in <(echo "$input"))
  local json=$(jq -n "{ \"awsm-crypto\": \"0.0.1\", key: \"$encrypted_key\", data: \"$data\"}")

  echoerr -e "\n= ENCRYPTED\n"
  echoerr "$json"

  echo "$json"
}

function decrypt {
  local input=$(cat)
  local encrypted_key=$(echo "$input" | jq -r ".key")
  local ciphertext=$(echo "$input" | jq -r ".data")
  local key=$(kms-decrypt $encrypted_key)
  echoerr -e "\n= DECRYPTED\n"
  echoerr "= KEY $key"

  local raw=$(openssl $AWSM_CRYPTO_OPENSSL_KEY_SPEC -k "$key" -d -in <(echo "$ciphertext" | base64 --decode))
  echoerr -e "\n= DECRYPTED MESSAGE\n"
  echo "$raw"
}
