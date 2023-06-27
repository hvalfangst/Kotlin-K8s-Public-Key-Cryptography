# Distributed Public Key Cryptosystem

Developed in Kotlin with Spring Boot and leveraged with Kubernetes


## Requirements

* x86-64
* Java 17 SDK
* Keytool
* Linux
* Docker
* Kubernetes
* Active Cluster 

## Creating resources
The shell script "up.sh" is responsible for building the local Docker image and creating requested resources, which are defined in our k8s manifest.

```
sh up.sh
```

## Destroying resources
The shell script "down.sh" frees up allocated resources.

```
sh down.sh
```

## Routes

Remember to port-forward to the designated pod before proceeding

### Data
POST http://localhost:8080/data/messageCounterpart


