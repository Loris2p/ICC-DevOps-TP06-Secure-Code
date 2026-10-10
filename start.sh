#!/usr/bin/env bash
set -e

# Création du venv python s'il n'existe pas déjà
if [ ! -d ".venv" ]; then
    python3.12 -m venv .venv #crash si absent
fi

# Activation du venv
source .venv/bin/activate

# Installation des dépendances
pip install --upgrade pip
pip install -r app/requirements.txt pytest bandit pip-audit
pip install "pydantic>=1.10.17,<2.0.0"

# Démarrage de l'app
cd app &&  python app.py
