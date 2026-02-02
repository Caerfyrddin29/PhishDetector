#!/usr/bin/env python3
import sys
sys.path.append('back')
from analyzer import analyzer

# Test French phishing scenarios
print("🇫🇷 Testing French Phishing Detection...")
print("=" * 50)

# Test 1: Urgent account suspension
french_urgent = '''URGENT: Votre compte sera suspendu immédiatement!

Veuillez vérifier vos informations de connexion dans les 24 heures 
ou votre compte sera définitivement fermé.

Action requise: Cliquez ici pour sécuriser votre compte.

Ne tardez pas! Cette offre expire bientôt.'''

result1 = analyzer.analyze(
    body=french_urgent,
    sender='security@banque-france.fr',
    metadata={'imageCount': 0, 'textLength': len(french_urgent)}
)

print("1. Test d'urgence de compte:")
print(f"Score: {result1['score']}")
print(f"Phishing: {result1['is_phishing']}")
print(f"Reasons: {result1['reasons']}")
print()

# Test 2: French investment scam
french_investment = '''Félicitations! Vous avez été sélectionné pour une opportunité unique!

Multipliez vos gains avec notre méthode secrète d'investissement.
Profit garanti de 500% en une semaine!

Gagnez 5000€ par jour depuis chez vous. Sans risque!
Travaillez seulement 2 heures par jour.

Liberté financière vous attend!

Agissez maintenant - places limitées!'''

result2 = analyzer.analyze(
    body=french_investment,
    sender='opportunité@invest-france.com',
    metadata={'imageCount': 0, 'textLength': len(french_investment)}
)

print("2. Test d'arnaque d'investissement:")
print(f"Score: {result2['score']}")
print(f"Phishing: {result2['is_phishing']}")
print(f"Reasons: {result2['reasons']}")
print()

# Test 3: French work from home scam
french_work = '''Tâche exclusive disponible!

Soyez votre propre patron et travaillez depuis chez vous.
Gagnez 2000€ par semaine avec des tâches simples.

Aucune expérience requise. Formation gratuite fournie.
Commencez dès aujourd'hui!

Places limitées - dépêchez-vous!'''

result3 = analyzer.analyze(
    body=french_work,
    sender='emploi@travail-domicile.fr',
    metadata={'imageCount': 0, 'textLength': len(french_work)}
)

print("3. Test d'arnaque de travail à domicile:")
print(f"Score: {result3['score']}")
print(f"Phishing: {result3['is_phishing']}")
print(f"Reasons: {result3['reasons']}")
print()

# Test 4: French legitimate email
french_legitimate = '''Bonjour Madame,

J'espère que vous allez bien.

Je vous confirme notre rendez-vous pour jeudi prochain à 10h00
dans nos bureaux à Paris.

N'oubliez pas d'apporter les documents nécessaires.

Cordialement,
Marie Laurent
Service Client
Entreprise ABC'''

result4 = analyzer.analyze(
    body=french_legitimate,
    sender='marie.laurent@entreprise-abc.fr',
    metadata={'imageCount': 0, 'textLength': len(french_legitimate)}
)

print("4. Test d'email légitime français:")
print(f"Score: {result4['score']}")
print(f"Phishing: {result4['is_phishing']}")
print(f"Reasons: {result4['reasons']}")
print()

# Test 5: Mixed content (legitimate + scam)
french_mixed = '''Bonjour cher client,

Nous sommes ravis de vous informer de notre nouvelle promotion
sur nos produits de beauté.

OFFRE SPÉCIALE: Gagnez 1000€ par jour avec notre méthode secrète!
Multipliez vos gains sans aucun risque. Profitez de cette opportunité unique!

N'hésitez pas à visiter notre site web pour plus d'informations.

Merci de votre fidélité.
L'équipe Beauté Plus'''

result5 = analyzer.analyze(
    body=french_mixed,
    sender='contact@beaute-plus.fr',
    metadata={'imageCount': 0, 'textLength': len(french_mixed)}
)

print("5. Test de contenu mixte:")
print(f"Score: {result5['score']}")
print(f"Phishing: {result5['is_phishing']}")
print(f"Reasons: {result5['reasons']}")

print(f"\n🎯 Résumé des tests français:")
print(f"Urgence: {result1['score']} pts ({'Phishing' if result1['is_phishing'] else 'Safe'})")
print(f"Investissement: {result2['score']} pts ({'Phishing' if result2['is_phishing'] else 'Safe'})")
print(f"Travail: {result3['score']} pts ({'Phishing' if result3['is_phishing'] else 'Safe'})")
print(f"Légitime: {result4['score']} pts ({'Phishing' if result4['is_phishing'] else 'Safe'})")
print(f"Mixte: {result5['score']} pts ({'Phishing' if result5['is_phishing'] else 'Safe'})")
