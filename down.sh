#!/bin/sh

# Exits immediately if a command exits with a non-zero status
set -e

echo

NUM_INSTANCES=2

for ((SERVER_NUMBER=1; SERVER_NUMBER<=$NUM_INSTANCES; SERVER_NUMBER++))
do
    echo -e "\n - - - - - - - - - - - - - - - - - - - - [SERVER #${SERVER_NUMBER}] - - - - - - - - - - - - - - - - - - - - - - - \n"

  KEYSTORE_SECRET="keystore-secret-${SERVER_NUMBER}"
  POD_IP_SECRET="service-secret-${SERVER_NUMBER}"
  PUBLIC_KEY_SECRET="public-key-secret-${SERVER_NUMBER}"
  MANIFEST="manifest-${SERVER_NUMBER}.yml"

  if kubectl get secret "$KEYSTORE_SECRET" >/dev/null 2>&1; then
      kubectl delete secrets ${KEYSTORE_SECRET}
  fi

  if kubectl get secret "$POD_IP_SECRET" >/dev/null 2>&1; then
      kubectl delete secrets ${POD_IP_SECRET}
  fi

  if kubectl get secret "$PUBLIC_KEY_SECRET" >/dev/null 2>&1; then
      kubectl delete secrets ${PUBLIC_KEY_SECRET}
  fi

  echo -e "\n\n"

  kubectl delete -f  k8s/${MANIFEST}

  echo -e "\n\n"
done