#!/usr/bin/env python3
import sys
sys.path.append('back')
from analyzer import analyzer

print("🏢 Testing French Business Email Compromise (BEC) Scenarios...")
print("=" * 60)

# Test 1: French CEO Fraud
french_ceo_fraud = '''Cher collègue,

J'espère que ce message vous trouve bien.

Je suis actuellement dans une réunion importante et ne peux pas 
utiliser mon téléphone. J'ai besoin de votre aide urgente.

Veuillez effectuer un virement bancaire de 15 000€ vers:
IBAN: FR76 3000 6000 1234 5678 9012 345
Bénéficiaire: Fournisseur Premium Services
Motif: Paiement urgent facture AC-2024-789

C'est absolument confidentiel et urgent. 
Veuillez me confirmer dès que le virement est effectué.

Cordialement,
Directeur Général
[CEO Name]
Société ABC'''

result1 = analyzer.analyze(
    body=french_ceo_fraud,
    sender='ceo@entreprise-abc.fr',
    metadata={'imageCount': 0, 'textLength': len(french_ceo_fraud)}
)

print("1. Test de fraude au PDG français:")
print(f"Score: {result1['score']}")
print(f"Phishing: {result1['is_phishing']}")
print(f"Reasons: {result1['reasons']}")
print()

# Test 2: French Bank Impersonation
french_bank_impersonation = '''Cher client,

Alerte de sécurité: Votre compte BNP Paribas a été compromis.

Nous avons détecté une activité suspecte sur votre compte:
- Connexion depuis une adresse IP inhabituelle
- Tentative de transfert vers un compte étranger
- Multiples échecs de connexion

Pour protéger votre compte, veuillez:
1. Cliquer immédiatement sur ce lien pour vérifier votre identité
2. Mettre à jour vos informations de sécurité
3. Confirmer vos transactions récentes

Lien sécurisé: https://bnp-paribas-securite.com/verification

Si vous n'agissez pas dans les 2 heures, votre compte sera suspendu.

Service Sécurité
BNP Paribas'''

result2 = analyzer.analyze(
    body=french_bank_impersonation,
    sender='securite@bnp-paribas.fr',
    metadata={'imageCount': 0, 'textLength': len(french_bank_impersonation)}
)

print("2. Test d'impersonation bancaire française:")
print(f"Score: {result2['score']}")
print(f"Phishing: {result2['is_phishing']}")
print(f"Reasons: {result2['reasons']}")
print()

# Test 3: French Tax Authority Scam
french_tax_scam = '''AVIS OFFICIEL - Direction Générale des Finances Publiques

Cher contribuable,

Notre système a détecté une incohérence dans votre déclaration d'impôts
pour l'année 2023.

Vous devez régler immédiatement un complément de 3 456,78€
pour éviter des pénalités de retard et des poursuites judiciaires.

Options de paiement:
1. Virement bancaire immédiat
2. Carte de crédit sécurisée
3. Paiement en ligne via notre portail sécurisé

Accès au paiement: https://impots.gouv.fr/paiement-urgent

Délai: 24 heures avant mise en recouvrement forcé.

Service Recouvrement
DGFP'''

result3 = analyzer.analyze(
    body=french_tax_scam,
    sender='recouvrement@dgfp.gouv.fr',
    metadata={'imageCount': 0, 'textLength': len(french_tax_scam)}
)

print("3. Test d'arnaque aux impôts français:")
print(f"Score: {result3['score']}")
print(f"Phishing: {result3['is_phishing']}")
print(f"Reasons: {result3['reasons']}")
print()

# Test 4: French Delivery Scam
french_delivery_scam = '''COLIS EN ATTENTE - Chronopost

Cher client,

Votre colis (référence: CZ123456789FR) est en attente de livraison.

Pour finaliser la livraison, veuillez payer les frais de douane
de 45,90€ en utilisant notre système de paiement sécurisé.

Détails du colis:
- Expéditeur: Boutique Parisienne
- Contenu: Articles de luxe
- Valeur déclarée: 250€
- Frais de douane: 45,90€

Paiement sécurisé: https://chronopost-paiement.com/frais-douane

Votre colis sera livré dans les 24h suivant le paiement.

Chronopost Service Client'''

result4 = analyzer.analyze(
    body=french_delivery_scam,
    sender='service@chronopost.fr',
    metadata={'imageCount': 0, 'textLength': len(french_delivery_scam)}
)

print("4. Test d'arnaque de livraison française:")
print(f"Score: {result4['score']}")
print(f"Phishing: {result4['is_phishing']}")
print(f"Reasons: {result4['reasons']}")
print()

# Test 5: Legitimate French Business Email
french_legitimate = '''Bonjour Madame,

Suite à notre conversation téléphonique de ce matin,
je vous confirme notre rendez-vous pour mardi prochain à 14h00
dans nos bureaux de Paris.

Ordre du jour:
- Présentation du nouveau projet marketing
- Discussion du budget Q4 2024
- Validation des prochaines étapes

N'hésitez pas à me contacter si vous avez besoin d'informations
supplémentaires.

Cordialement,
Pierre Martin
Directeur Marketing
Société Innovation France'''

result5 = analyzer.analyze(
    body=french_legitimate,
    sender='p.martin@innovation-france.fr',
    metadata={'imageCount': 0, 'textLength': len(french_legitimate)}
)

print("5. Test d'email d'affaires légitime français:")
print(f"Score: {result5['score']}")
print(f"Phishing: {result5['is_phishing']}")
print(f"Reasons: {result5['reasons']}")

print(f"\n🎯 Résumé des tests BEC français:")
print(f"Fraude PDG: {result1['score']} pts ({'Phishing' if result1['is_phishing'] else 'Safe'})")
print(f"Banque: {result2['score']} pts ({'Phishing' if result2['is_phishing'] else 'Safe'})")
print(f"Impôts: {result3['score']} pts ({'Phishing' if result3['is_phishing'] else 'Safe'})")
print(f"Livraison: {result4['score']} pts ({'Phishing' if result4['is_phishing'] else 'Safe'})")
print(f"Légitime: {result5['score']} pts ({'Phishing' if result5['is_phishing'] else 'Safe'})")

print(f"\n📊 Performance de détection française:")
total_tests = 5
phishing_detected = sum(1 for r in [result1, result2, result3, result4, result5] if r['is_phishing'])
print(f"Taux de détection: {phishing_detected}/{total_tests} ({phishing_detected/total_tests*100:.0f}%)")
