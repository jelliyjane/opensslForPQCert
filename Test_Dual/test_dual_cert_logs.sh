#!/bin/bash

# Script de test pour vérifier l'encodage et le décodage des certificats duales
# avec logs détaillés

set -e

echo "=== Test des certificats duales avec logs détaillés ==="

# Variables d'environnement pour OpenSSL 3.3.0 + OQS provider
export PATH=/usr/local/ssl/bin:$PATH
export LD_LIBRARY_PATH=/usr/local/ssl/lib64:$LD_LIBRARY_PATH
export PKG_CONFIG_PATH=/usr/local/ssl/lib64/pkgconfig
export OPENSSL_MODULES=/usr/local/ssl/lib64/ossl-modules

# Vérifier que les certificats existent
if [ ! -f "server_cert.pem" ] || [ ! -f "server_key.pem" ]; then
    echo "ERROR: Certificats serveur manquants. Exécutez d'abord gen_dual_certs.sh"
    exit 1
fi

if [ ! -f "pqc_cert.pem" ] || [ ! -f "pqc_key.pem" ]; then
    echo "ERROR: Certificats PQC manquants. Exécutez d'abord gen_dual_certs.sh"
    exit 1
fi

echo "1. Démarrage du serveur avec certificats duales..."
echo "   - Certificat classique: server_cert.pem"
echo "   - Certificat PQC: pqc_cert.pem"
echo "   - Mode dual activé"

# Démarrer le serveur en arrière-plan avec logs détaillés
../apps/openssl s_server \
    -accept 8444 \
    -cert server_cert.pem \
    -key server_key.pem \
    -pqcert pqc_cert.pem \
    -pqkey pqc_key.pem \
    -dual-certs \
    -debug \
    -msg \
    -verify_return_error \
    -CAfile ca_cert.pem \
    -cipher ALL \
    -tls1_2 \
    -quiet &
SERVER_PID=$!

# Attendre que le serveur démarre
sleep 2

echo ""
echo "2. Test de connexion client avec logs détaillés..."
echo "   - Connexion au serveur sur localhost:8444"
echo "   - Vérification des certificats duales"

# Test de connexion client avec logs détaillés
../apps/openssl s_client \
    -connect localhost:8444 \
    -CAfile ca_cert.pem \
    -debug \
    -msg \
    -verify_return_error \
    -cipher ALL \
    -tls1_2 \
    -quiet

echo ""
echo "3. Vérification des logs..."

# Arrêter le serveur
echo "Arrêt du serveur..."
kill $SERVER_PID 2>/dev/null || true
wait $SERVER_PID 2>/dev/null || true

echo ""
echo "=== Analyse des logs ==="
echo ""
echo "Les logs suivants devraient apparaître si l'encodage/décodage fonctionne :"
echo ""
echo "Côté serveur (encodage) :"
echo "  [DUAL_CERT_SERVER] Starting dual certificate encoding"
echo "  [DUAL_CERT_SERVER] Encoding classic certificate chain"
echo "  [DUAL_CERT_SERVER] Classic certificate chain encoded successfully"
echo "  [DUAL_CERT_SERVER] Adding delimiter (0x00 0x00 0x00)"
echo "  [DUAL_CERT_SERVER] Delimiter added successfully"
echo "  [DUAL_CERT_SERVER] Encoding PQC certificate chain"
echo "  [DUAL_CERT_SERVER] PQC certificate chain encoded successfully"
echo "  [DUAL_CERT_SERVER] Dual certificate encoding completed successfully"
echo ""
echo "Côté client (décodage) :"
echo "  [DUAL_CERT_CLIENT] Starting server certificate processing"
echo "  [DUAL_CERT_DETECT] SUCCESS: Dual certificate delimiter found!"
echo "  [DUAL_CERT_CLIENT] Dual certificate delimiter detected!"
echo "  [CLASSIC_CHAIN] Starting classic certificate chain processing"
echo "  [CLASSIC_CHAIN] Classic certificate chain processing completed successfully"
echo "  [PQC_CHAIN] Starting PQC certificate chain processing"
echo "  [PQC_CHAIN] PQC certificate chain processing completed successfully"
echo "  [DUAL_CERT_CLIENT] Dual certificate mode enabled in session"
echo ""
echo "Signatures duales :"
echo "  [DUAL_SIGN_SERVER] Dual certificate mode detected, preparing dual signatures"
echo "  [DUAL_SIGN_SERVER] Classic signature created successfully"
echo "  [DUAL_SIGN_SERVER] PQC signature created successfully"
echo "  [DUAL_SIGN_SERVER] Combining classic and PQC signatures"
echo "  [DUAL_SIGN_CLIENT] Detected dual signature"
echo "  [DUAL_SIGN_CLIENT] Classic signature verification successful"
echo "  [DUAL_SIGN_CLIENT] PQC signature verification successful"
echo ""

echo "=== Test terminé ==="
echo ""
echo "Si vous voyez ces messages dans les logs, cela signifie que :"
echo "1. Les certificats duales sont correctement encodés côté serveur"
echo "2. Le délimiteur est correctement ajouté"
echo "3. Les certificats duales sont correctement décodés côté client"
echo "4. Les signatures duales sont créées et vérifiées"
echo ""
echo "Si certains messages n'apparaissent pas, cela indique un problème"
echo "dans l'implémentation correspondante." 