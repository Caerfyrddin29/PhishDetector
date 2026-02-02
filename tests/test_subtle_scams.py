#!/usr/bin/env python3
import sys
sys.path.append('back')
from analyzer import analyzer

print("🎭 Testing Subtle Scam Emails - Advanced Evasion Techniques")
print("=" * 65)

# Test 1: Sophisticated Business Email Compromise (BEC) - No obvious keywords
subtle_bec = '''Hi Sarah,

Hope you're having a productive week.

I need you to process an urgent vendor payment for Project Phoenix.
The vendor has updated their banking details at the last minute due to
technical issues with their previous account.

New Banking Information:
Bank: Wells Fargo
Account Name: Phoenix Tech Solutions LLC
Account Number: 4872936472
Routing Number: 121042882
Amount: $24,750.00

Please process this today as it's holding up the project timeline.
I've attached the updated invoice for your records.

Let me know once it's completed.

Best regards,
Michael Chen
Project Director
Phoenix Corporation'''

result1 = analyzer.analyze(
    body=subtle_bec,
    links=[],
    sender='michael.chen@phoenix-corp.com',
    metadata={'imageCount': 0, 'textLength': len(subtle_bec)}
)

print("1. Subtle BEC - No obvious urgency keywords:")
print(f"Score: {result1['score']}/100")
print(f"Phishing: {result1['is_phishing']}")
print(f"Reasons: {result1['reasons']}")
print()

# Test 2: "Too Good to Be True" Investment - Professional language
professional_investment = '''Dear Valued Client,

We are pleased to present an exclusive investment opportunity
in our Quantum Computing Fund, which has demonstrated consistent
outperformance of traditional market indices.

Performance Highlights:
- 5-year average return: 28.7% annually
- Minimum investment: $10,000
- Risk rating: Moderate (B+)
- Fund manager: Dr. Sarah Williams, PhD MIT

Our proprietary algorithm leverages quantum computing principles
to identify market inefficiencies before they become widely known.

Limited availability: We are accepting only 50 new investors this quarter
to maintain fund performance and exclusivity.

Schedule a consultation with our investment advisors at your convenience.

Sincerely,
Wealth Management Team
Quantum Capital Partners'''

result2 = analyzer.analyze(
    body=professional_investment,
    links=[{'href': 'quantum-capital-partners.com/invest', 'text': 'Learn More'}],
    sender='info@quantum-capital-partners.com',
    metadata={'imageCount': 0, 'textLength': len(professional_investment)}
)

print("2. Professional Investment Scam:")
print(f"Score: {result2['score']}/100")
print(f"Phishing: {result2['is_phishing']}")
print(f"Reasons: {result2['reasons']}")
print()

# Test 3: Technical Support Impersonation - Uses legitimate-looking domain
tech_support = '''Dear Customer,

Our security monitoring system has detected unusual login activity
on your Microsoft 365 account.

Details:
- Location: Unknown IP address in Eastern Europe
- Time: 3:47 AM EST
- Device: Unrecognized mobile device

To secure your account, please verify your identity by clicking below:
https://microsoft365-security.azurewebsites.net/verify

If this wasn't you, your account will be temporarily suspended
within 24 hours for your protection.

Microsoft Security Team
One Microsoft Way
Redmond, WA 98052'''

result3 = analyzer.analyze(
    body=tech_support,
    links=[{'href': 'https://microsoft365-security.azurewebsites.net/verify', 'text': 'Verify Account'}],
    sender='security@microsoft.com',
    metadata={'imageCount': 0, 'textLength': len(tech_support)}
)

print("3. Tech Support Impersonation:")
print(f"Score: {result3['score']}/100")
print(f"Phishing: {result3['is_phishing']}")
print(f"Reasons: {result3['reasons']}")
print()

# Test 4: Romance Scam - Emotional manipulation without obvious scam words
romance_scam = '''Hello my dear,

I hope this message finds you well. I've been thinking about our
conversation yesterday, and I feel we have a special connection.

I wanted to share something personal with you. I recently received
a large inheritance from my grandmother's estate, but there are
some complications with the legal process here in Nigeria.

The lawyers need $5,000 for documentation fees to release the funds.
Once that's cleared, I'll have $250,000 and we can finally meet in person
and start our life together.

I've already booked flights to come see you next month. This money
is just a temporary hurdle before we can be together forever.

Trust me when I say you're the one for me. I've never felt this way
about anyone before.

With all my love,
Isabella'''

result4 = analyzer.analyze(
    body=romance_scam,
    links=[],
    sender='isabella.romance84@gmail.com',
    metadata={'imageCount': 0, 'textLength': len(romance_scam)}
)

print("4. Romance Scam - Emotional Manipulation:")
print(f"Score: {result4['score']}/100")
print(f"Phishing: {result4['is_phishing']}")
print(f"Reasons: {result4['reasons']}")
print()

# Test 5: Charity Scam - Uses current events and legitimate-looking info
charity_scam = '''Subject: Help Ukraine Refugee Children - Emergency Appeal

Dear Friend,

The situation for Ukrainian children has reached critical levels.
With winter approaching, thousands of refugee children are without
warm clothing, food, or medical care.

Our organization, Ukraine Children's Relief Fund, has been working
on the ground since day one of the crisis. We've helped over 50,000
children, but the need is overwhelming.

Your donation of just $50 can provide:
- Warm winter coat for a child
- Food for one week
- Basic medical supplies

We're a registered 501(c)(3) organization (EIN: 83-1234567).
100% of your donation goes directly to helping children.

Click here to make a tax-deductible donation:
https://ukraine-children-relief.org/donate

Time is critical. Children are suffering as we speak.

With gratitude,
Dr. Elena Petrov
Director of Operations
Ukraine Children's Relief Fund'''

result5 = analyzer.analyze(
    body=charity_scam,
    links=[{'href': 'https://ukraine-children-relief.org/donate', 'text': 'Donate Now'}],
    sender='dr.petrov@ukraine-children-relief.org',
    metadata={'imageCount': 0, 'textLength': len(charity_scam)}
)

print("5. Charity Scam - Emotional Appeal:")
print(f"Score: {result5['score']}/100")
print(f"Phishing: {result5['is_phishing']}")
print(f"Reasons: {result5['reasons']}")
print()

# Test 6: Job Offer Scam - Professional but suspicious
job_offer = '''Dear Candidate,

Following our review of your LinkedIn profile, we're impressed with
your qualifications and would like to offer you a position at
Global Tech Innovations Inc.

Position: Remote Data Entry Specialist
Salary: $85,000/year + benefits
Start Date: Immediate
Location: 100% Remote

Your responsibilities will include:
- Processing confidential company documents
- Managing sensitive customer data
- Coordinating with international teams

To begin the onboarding process, you'll need to complete our
background check and direct deposit setup. Please click here to
access our secure employee portal:

https://globaltech-hr.secure-onboarding.com/employee-portal

You'll need to provide:
- Social Security Number
- Bank account information
- Driver's license copy

We're excited to welcome you to our team!

HR Department
Global Tech Innovations Inc.
Fortune 500 Company'''

result6 = analyzer.analyze(
    body=job_offer,
    links=[{'href': 'https://globaltech-hr.secure-onboarding.com/employee-portal', 'text': 'Employee Portal'}],
    sender='hr@globaltech-innovations.com',
    metadata={'imageCount': 0, 'textLength': len(job_offer)}
)

print("6. Job Offer Scam - Professional but Suspicious:")
print(f"Score: {result6['score']}/100")
print(f"Phishing: {result6['is_phishing']}")
print(f"Reasons: {result6['reasons']}")

print(f"\n🎯 Subtle Scam Detection Summary:")
print(f"BEC Attack: {result1['score']} pts ({'Detected' if result1['is_phishing'] else 'Missed'})")
print(f"Investment: {result2['score']} pts ({'Detected' if result2['is_phishing'] else 'Missed'})")
print(f"Tech Support: {result3['score']} pts ({'Detected' if result3['is_phishing'] else 'Missed'})")
print(f"Romance: {result4['score']} pts ({'Detected' if result4['is_phishing'] else 'Missed'})")
print(f"Charity: {result5['score']} pts ({'Detected' if result5['is_phishing'] else 'Missed'})")
print(f"Job Offer: {result6['score']} pts ({'Detected' if result6['is_phishing'] else 'Missed'})")

subtle_detected = sum(1 for r in [result1, result2, result3, result4, result5, result6] if r['is_phishing'])
print(f"\n📊 Subtle Scam Detection Rate: {subtle_detected}/6 ({subtle_detected/6*100:.0f}%)")

if subtle_detected < 4:
    print("⚠️  WARNING: Low detection rate for sophisticated scams!")
    print("🔧 Consider enhancing detection for:")
    print("   - BEC patterns without obvious keywords")
    print("   - Professional-looking investment scams")
    print("   - Domain impersonation techniques")
    print("   - Emotional manipulation patterns")
else:
    print("✅ Good detection rate for sophisticated scams!")
