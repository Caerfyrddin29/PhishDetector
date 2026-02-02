#!/usr/bin/env python3
import sys
sys.path.append('back')
from analyzer import analyzer

print("🎭 Testing French Subtle Scams - Techniques d'Évasion Avancées")
print("=" * 65)

# Test 1: French BEC - Professional language
french_bec = '''Bonjour Marie,

J'espère que vous allez bien cette semaine.

J'ai besoin que vous traitiez un paiement urgent pour notre fournisseur
Technologie Solutions. Le fournisseur a mis à jour ses coordonnées bancaires
à la dernière minute en raison de problèmes techniques avec leur compte précédent.

Nouvelles informations bancaires:
Banque: BNP Paribas
Nom du compte: Tech Solutions SARL
IBAN: FR76 3000 6000 1234 5678 9012 345
Montant: 45 750,00 €

Veuillez traiter ce paiement aujourd'hui car il retarde le projet.
J'ai joint la facture mise à jour pour vos dossiers.

Faites-moi savoir une fois terminé.

Cordialement,
Jean Dupont
Directeur de Projet
Société Française'''

result1 = analyzer.analyze(
    body=french_bec,
    links=[],
    sender='jean.dupont@societe-francaise.fr',
    metadata={'imageCount': 0, 'textLength': len(french_bec)}
)

print("1. BEC Français - Langage professionnel:")
print(f"Score: {result1['score']}/100")
print(f"Phishing: {result1['is_phishing']}")
print(f"Reasons: {result1['reasons']}")
print()

# Test 2: French Investment Scam
french_investment = '''Cher Investisseur,

Nous sommes ravis de vous présenter une opportunité d'investissement exclusive
dans notre Fonds Quantique, qui a démontré une performance constante
supérieure aux indices de marché traditionnels.

Points forts de performance:
- Rendement moyen sur 5 ans: 32,4% annuellement
- Investissement minimum: 15 000 €
- Note de risque: Modéré (B+)
- Gérant: Dr. Sophie Martin, PhD Polytechnique

Notre algorithme propriétaire exploite les principes de l'informatique quantique
pour identifier les inefficacités du marché avant qu'elles ne deviennent largement connues.

Disponibilité limitée: Nous n'acceptons que 30 nouveaux investisseurs ce trimestre
pour maintenir la performance et l'exclusivité du fonds.

Prenez rendez-vous avec nos conseillers en investissement à votre convenance.

Sincèrement,
Équipe de Gestion de Patrimoine
Capital Quantique France'''

result2 = analyzer.analyze(
    body=french_investment,
    links=[{'href': 'capital-quantique.fr/investir', 'text': 'En Savoir Plus'}],
    sender='info@capital-quantique.fr',
    metadata={'imageCount': 0, 'textLength': len(french_investment)}
)

print("2. Arnaque à l'Investissement Française:")
print(f"Score: {result2['score']}/100")
print(f"Phishing: {result2['is_phishing']}")
print(f"Reasons: {result2['reasons']}")
print()

# Test 3: French Tech Support Scam
french_tech = '''Cher Client,

Notre système de surveillance de sécurité a détecté une activité de connexion
inhabituelle sur votre compte Microsoft 365.

Détails:
- Localisation: Adresse IP inconnue en Europe de l'Est
- Heure: 4h47 du matin
- Appareil: Appareil mobile non reconnu

Pour sécuriser votre compte, veuillez vérifier votre identité en cliquant ci-dessous:
https://microsoft365-securite.azurewebsites.net/verifier

Si ce n'était pas vous, votre compte sera temporairement suspendu
dans 24 heures pour votre protection.

Équipe de Sécurité Microsoft
Microsoft France'''

result3 = analyzer.analyze(
    body=french_tech,
    links=[{'href': 'https://microsoft365-securite.azurewebsites.net/verifier', 'text': 'Vérifier le Compte'}],
    sender='securite@microsoft.com',
    metadata={'imageCount': 0, 'textLength': len(french_tech)}
)

print("3. Arnaque Support Technique Français:")
print(f"Score: {result3['score']}/100")
print(f"Phishing: {result3['is_phishing']}")
print(f"Reasons: {result3['reasons']}")
print()

# Test 4: French Romance Scam
french_romance = '''Bonjour mon amour,

J'espère que ce message te trouve bien. Je pense à notre conversation
d'hier, et je sens que nous avons une connexion spéciale.

Je voulais te partager quelque chose de personnel. J'ai récemment reçu
un héritage important de ma grand-mère, mais il y a des complications
avec le processus légal ici au Nigéria.

Les avocats ont besoin de 4 000 € pour les frais de documentation
pour libérer les fonds. Une fois que ce sera réglé, j'aurai 200 000 €
et nous pourrons enfin nous rencontrer en personne et commencer notre vie ensemble.

J'ai déjà réservé des billets d'avion pour venir te voir le mois prochain.
Cet argent est juste un obstacle temporaire avant que nous puissions être ensemble pour toujours.

Fais-moi confiance quand je te dis que tu es la bonne personne.
Je n'ai jamais ressenti ça pour personne d'autre.

Avec tout mon amour,
Isabelle'''

result4 = analyzer.analyze(
    body=french_romance,
    links=[],
    sender='isabelle.romance84@gmail.com',
    metadata={'imageCount': 0, 'textLength': len(french_romance)}
)

print("4. Arnaque Romantique Française:")
print(f"Score: {result4['score']}/100")
print(f"Phishing: {result4['is_phishing']}")
print(f"Reasons: {result4['reasons']}")
print()

# Test 5: French Charity Scam
french_charity = '''Objet: Aidez les Enfants Réfugiés d'Ukraine - Appel d'Urgence

Cher Ami,

La situation pour les enfants ukrainiens a atteint des niveaux critiques.
Avec l'hiver qui approche, des milliers d'enfants réfugiés sont sans
vêtements chauds, nourriture, ou soins médicaux.

Notre organisation, Secours Enfants Ukraine, travaille sur le terrain
depuis le premier jour de la crise. Nous avons aidé plus de 45 000
enfants, mais le besoin est écrasant.

Votre don de seulement 40 € peut fournir:
- Manteau d'hiver pour un enfant
- Nourriture pour une semaine
- Fournitures médicales de base

Nous sommes une association loi 1901 (SIREN: 123456789).
100% de votre don va directement aux enfants.

Cliquez ici pour faire un don déductible des impôts:
https://secours-enfants-ukraine.org/donner

Le temps est critique. Les enfants souffrent en ce moment même.

Avec gratitude,
Dr. Elena Petrova
Directrice des Opérations
Secours Enfants Ukraine'''

result5 = analyzer.analyze(
    body=french_charity,
    links=[{'href': 'https://secours-enfants-ukraine.org/donner', 'text': 'Faire un Don'}],
    sender='dr.petrova@secours-enfants-ukraine.org',
    metadata={'imageCount': 0, 'textLength': len(french_charity)}
)

print("5. Arnaque Caritative Française:")
print(f"Score: {result5['score']}/100")
print(f"Phishing: {result5['is_phishing']}")
print(f"Reasons: {result5['reasons']}")

print(f"\n🎯 Résumé Détection Arnaques Subtiles Françaises:")
print(f"BEC: {result1['score']} pts ({'Détecté' if result1['is_phishing'] else 'Manqué'})")
print(f"Investissement: {result2['score']} pts ({'Détecté' if result2['is_phishing'] else 'Manqué'})")
print(f"Support Tech: {result3['score']} pts ({'Détecté' if result3['is_phishing'] else 'Manqué'})")
print(f"Romance: {result4['score']} pts ({'Détecté' if result4['is_phishing'] else 'Manqué'})")
print(f"Caritatif: {result5['score']} pts ({'Détecté' if result5['is_phishing'] else 'Manqué'})")

french_detected = sum(1 for r in [result1, result2, result3, result4, result5] if r['is_phishing'])
print(f"\n📊 Taux de Détection Français: {french_detected}/5 ({french_detected/5*100:.0f}%)")
