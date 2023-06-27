#!/bin/sh

# Exits immediately if a command exits with a non-zero status
set -e

NUM_INSTANCES=2
APP="first-server"

# Build docker image
  echo "[Building image [kotlin-crypto] from Dockerfile]"
  if ! docker build -t hardokkerdokker/hvalfangst:kotlin-crypto .; then
    echo
    echo "[Error building image 'kotlin-crypto' - Exiting script]"
    exit 1
  else
    echo -e "\n\n"
  fi

for ((SERVER_NUMBER=1; SERVER_NUMBER<=$NUM_INSTANCES; SERVER_NUMBER++))
do
  echo -e "\n - - - - - - - - - - - - - - - - - - - - [SERVER #${SERVER_NUMBER}] - - - - - - - - - - - - - - - - - - - - - - - \n"

  KEYSTORE_ALIAS="server_${SERVER_NUMBER}_key"
  KEYSTORE_PASSWORD="changeit"
  KEYSTORE_FILE="keystores/server_${SERVER_NUMBER}_keystore.p12"
  KEYSTORE_PATH="src/main/resources/server_${SERVER_NUMBER}_keystore.p12"
  PUBLIC_KEY_SECRET="public-key-secret-${SERVER_NUMBER}"

  # Check if the keystore alias already exists
  if keytool -list -alias "$KEYSTORE_ALIAS" -keystore "$KEYSTORE_FILE" -storepass "$KEYSTORE_PASSWORD" >/dev/null 2>&1; then
    echo -e "[Keystore alias '$KEYSTORE_ALIAS' already exists. Skipping key pair generation for server ${SERVER_NUMBER}].\n\n"
  else
    # Generate RSA key pair using keytool
    keytool -genkeypair -alias "$KEYSTORE_ALIAS" -keyalg RSA -keysize 2048 -keystore "$KEYSTORE_FILE" -storetype PKCS12 -storepass "$KEYSTORE_PASSWORD" -validity 365 -dname "CN=Server #${SERVER_NUMBER}"

     echo -e "\n\n"
  fi


  # Extract the public key from the newly generated keystore
  PUBLIC_KEY=$(keytool -exportcert -alias "$KEYSTORE_ALIAS" -keystore "$KEYSTORE_FILE" -storepass "$KEYSTORE_PASSWORD" -rfc)

  echo -e "\n\n PUBLIC_KEY: ${PUBLIC_KEY}"

  KEYSTORE_SECRET="keystore-secret-${SERVER_NUMBER}"

  # Check if the secret already exists
  if kubectl get secret "$KEYSTORE_SECRET" >/dev/null 2>&1; then
    echo "[Secret $KEYSTORE_SECRET already exists. Skipping creation for server ${SERVER_NUMBER}.]"
  else
    echo "[Creating secret $KEYSTORE_SECRET for server ${SERVER_NUMBER}]"

    # Create the Kubernetes secret
    kubectl create secret generic "$KEYSTORE_SECRET" \
      --from-file=server_"$SERVER_NUMBER"_keystore.p12="$KEYSTORE_FILE" \
      --from-literal=path="$KEYSTORE_PATH" \
      --from-literal=password="$KEYSTORE_PASSWORD" \
      --from-literal=alias="$KEYSTORE_ALIAS"
  fi

   echo -e "\n\n"


    if kubectl get secret "$PUBLIC_KEY_SECRET" >/dev/null 2>&1; then
       echo "[Secret $PUBLIC_KEY_SECRET already exists. Skipping creation for server ${SERVER_NUMBER}.]"
     else
       echo "[Creating secret $PUBLIC_KEY_SECRET for server ${SERVER_NUMBER}]"

       # Create the Kubernetes secret for public key
       kubectl create secret generic "$PUBLIC_KEY_SECRET" --from-literal=public-key.cer="$PUBLIC_KEY"
     fi


  echo -e "\n\n"

  # Create K8s resources based on manifest files
  kubectl apply -f k8s/manifest-"$SERVER_NUMBER".yml
   echo -e "\n\n"

   wait

   if ((SERVER_NUMBER > 1)); then
      APP="second-server"
   fi

    sleep 2

    SERVICE_NAME="${APP}-service:8080"
    SERVICE_SECRET="service-secret-${SERVER_NUMBER}"
    kubectl create secret generic "$SERVICE_SECRET" --from-literal=ip="$SERVICE_NAME" --dry-run=client -o yaml | kubectl apply -f -
    echo -e "[Created secret $SERVICE_SECRET with service name $SERVICE_NAME for server ${SERVER_NUMBER}]\n\n"


done

# List pods
kubectl get pods
