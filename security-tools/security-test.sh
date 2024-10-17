#!/bin/bash

echo "Démarrage des tests de sécurité..."

# Test des dépendances avec Snyk
echo "Analyse des dépendances du backend..."
cd BackendPfe
snyk test

echo "Analyse des dépendances du frontend..."
cd ../FrontPfe
snyk test

# Scan OWASP ZAP
echo "Démarrage du scan OWASP ZAP..."
./ZAP_2.14.0/zap.sh -cmd \
    -quickurl http://localhost:3000 \
    -quickprogress \
    -quickout zap-report.html

echo "Tests de sécurité terminés. Consultez les rapports générés."
