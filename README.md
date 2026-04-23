# Mock Banking System

This project is a Docker-based mock banking environment for simulating cyber attacks and evaluating defence options.

## Overview

The system allows you to:

- run a mock banking web application
- execute different threat models from a separate attacker container
- enable or disable defence systems in `docker/docker-compose.yml`
- compare system behaviour before and after applying each defence

## Software Versions

- Python: 3.11
- Flask: 3.1.3
- requests: 2.33.0

These versions are consistent with the current project setup and dependency list.

## Prerequisites

Install Docker Desktop first:

`https://www.docker.com/products/docker-desktop/`

Make sure Docker Desktop is running before starting the project.

## Project Structure

A typical structure for running this project is:

```text
project_root/
├── docker/
│   ├── docker-compose.yml
│   ├── Dockerfile.server
│   └── Dockerfile.attacker
├── attacks/
├── data/
├── templates/
├── app.py
├── banking_system.py
├── models.py
├── mfa_mailer.py
├── run.py
├── requirements.txt
└── environment.yml
```

## Project Setup

Open Terminal 1 and run:

```bash
cd docker
docker compose down
docker compose up --build
```

This stops any existing containers and rebuilds the environment.

## Run the Banking Server

Open Terminal 2 and run:

```bash
cd docker
docker exec -it banking_server python3 run.py
```

To restart the server, run:

```bash
docker compose restart banking_server
```

If you update the code and need to rebuild the containers, go back to Terminal 1 and run:

```bash
cd docker
docker compose down
docker compose up --build
```

## Threat Models

Choose one threat model to run in Terminal 2.

### Threat 1 — Account Takeover

```bash
docker exec -it attacker python3 attacks/account_takeover.py
```

### Threat 2 — HTTP DoS

```bash
docker exec -it attacker python3 attacks/http_dos.py
```

### Threat 3 — Data Exfiltration

```bash
docker exec -it attacker python3 attacks/data_exfiltration.py
```

## Defence Configuration

In `docker/docker-compose.yml`, you can turn defence systems on or off by changing the values below:

```yaml
# Threat 1 — Account Takeover
- DEFENSE_MFA=false
- DEFENSE_PASSWORD_HASH=false
- DEFENSE_TRANSFER_GUARD=false
- TRANSFER_GUARD_THRESHOLD=3000

# Threat 2 — HTTP Flood
- DEFENSE_RATE_LIMIT=false

# Threat 3 — Data Exfiltration
- DEFENSE_SESSION_AUTH=false
- DEFENSE_DATA_MIN=false
```

To enable a defence, change `false` to `true`.

Example:

```yaml
- DEFENSE_MFA=true
```

## Important Note

Enable one defence at a time when evaluating results.

The system can technically run with multiple defences enabled together, but that makes it harder to clearly show the impact of each individual defence in a controlled comparison.

## Access the Website

After Terminal 1 and Terminal 2 are both running, you can access the mock banking system at:

- Login page: `http://localhost:5001/login`
- Audit log: `http://localhost:5001/audit`

## Recommended Workflow

1. Start the Docker containers in Terminal 1.
2. Start the banking server in Terminal 2.
3. Run one attack script from the attacker container.
4. Observe the result.
5. Enable the corresponding defence in `docker/docker-compose.yml`.
6. Restart or rebuild the environment if needed.
7. Run the same attack again.
8. Compare the results before and after the defence is enabled.

## Optional Conda Environment

Docker is the recommended way to run this project. However, if you want a local Python environment for testing or development, you can use Conda in either of the following two ways.

### Option 1 — Use `environment.yml`

If you have an `environment.yml` file, you can create the environment directly with:

```bash
conda env create -f environment.yml
conda activate myenv
```

Example `environment.yml`:

```yaml
name: myenv
dependencies:
  - python=3.11
  - pip
  - pip:
      - Flask==3.1.3
      - requests==2.33.0
```

### Option 2 — Use `requirements.txt`

You can also create a Conda environment first and then install dependencies from `requirements.txt`:

```bash
pip install -r requirements.txt
```

Depending on your folder layout, you may need to adjust paths or environment variables when running locally.

## Notes

- Use `docker compose up --build` when code changes require rebuilding the container.
- Use `docker compose restart banking_server` when you only need to restart the server.
- Check the audit page to monitor system activity and security-related events during testing.
- The project includes both web routes and API routes for demonstrating normal banking behaviour and attack scenarios.
=======
Example `requirements.txt`:

```txt
Flask==3.1.3
requests==2.33.0
```

Important notes:

- Python 3.11 should be specified when creating the Conda environment, for example with `conda create -n mock-banking-system python=3.11`.
- `requirements.txt` should contain Python packages such as Flask and requests.
- Do not write `python=3.11` inside `requirements.txt`.
- If you want to specify the Python version in a file, use `environment.yml` instead.

## Local Run Notes


