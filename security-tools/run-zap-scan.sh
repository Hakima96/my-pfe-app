#!/bin/bash
./ZAP_2.14.0/zap.sh -daemon -config api.key=12345 -port 8080 &
sleep 10

# Scan du frontend
curl "http://localhost:8080/JSON/spider/action/scan/?apikey=12345&url=http://localhost:3000"
# Scan du backend
curl "http://localhost:8080/JSON/spider/action/scan/?apikey=12345&url=http://localhost:5000"

# Génération du rapport
curl "http://localhost:8080/OTHER/core/other/jsonreport/?apikey=12345" > security-report.json
