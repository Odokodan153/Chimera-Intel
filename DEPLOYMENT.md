# Chimera Intel - Production Deployment Guide

This guide provides a comprehensive overview of how to deploy the Chimera Intel application in a production environment.

## 1. Prerequisites

- A running instance of **PostgreSQL**.
- A running instance of **HashiCorp Vault**.
- A container orchestration platform like **Kubernetes** or **Docker Compose**.

## 2. Secret Management with HashiCorp Vault

For production, it is crucial to use a secure secret management system like HashiCorp Vault.

1.  **Store your secrets** (API keys, database credentials, etc.) in a Vault KV store. The recommended path is `kv/data/chimera-intel`.

2.  **Set the following environment variables** in your container orchestration system to allow the application to connect to Vault:
    - `VAULT_ADDR`: The URL of your Vault server.
    - `VAULT_TOKEN`: A valid Vault access token.
    - `VAULT_SECRET_PATH`: The path to your secrets in Vault.

## 3. Database Configuration

The application is configured to use PostgreSQL in production.

- **Set the following environment variables** to connect to your database:
  - `DB_HOST`: The hostname or IP address of your PostgreSQL server.
  - `DB_USER`: The database username.
  - `DB_PASSWORD`: The database password.
  - `DB_NAME`: The name of the database.

## 4. Logging and Monitoring

The application uses a structured JSON logging format, which is ideal for production monitoring.

- **Configure your container to stream logs** to a centralized logging platform like the **ELK Stack (Elasticsearch, Logstash, Kibana)** or **Datadog**.

- **Set up alerts** in your monitoring platform to be notified of any `ERROR` or `CRITICAL` level logs.

## 5. Running the Application

- **Build the Docker image** using the provided `Dockerfile`.
- **Push the image** to a container registry (e.g., Docker Hub, Amazon ECR).
- **Deploy the image** to your container orchestration platform, ensuring that all the environment variables from the steps above are correctly set.

By following these steps, you can deploy a secure, robust, and observable instance of the Chimera Intel application.