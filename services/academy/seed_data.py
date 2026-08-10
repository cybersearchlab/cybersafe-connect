"""
services/academy/seed_data.py
================================================================================
CyberSafe Connect Academy Microservice
================================================================================

Populate academy database with initial modules and quiz content.

Responsibilities:
    • Insert academy learning modules
    • Insert quiz questions
    • Insert answer choices
    • Update existing modules safely

Run:
    python seed_data.py

This file MUST NOT contain:
    • API routes
    • Authentication logic
    • Business logic unrelated to seed operations

Seed academy modules and quiz data (converted from Django load_academy_data).
Run: python seed_data.py

================================================================================
"""

from database import SessionLocal, engine, Base
from enums import TargetRole
from models import Choice, Module, Question

MODULES_DATA = [
    {
        "title": "Sécurité Mobile Money",
        "description": "Apprenez à sécuriser vos transactions Mobile Money au Cameroun.",
        "content": (
            "1. Ne partagez jamais votre code PIN, même avec un proche.\n"
            "2. Vérifiez toujours le nom du destinataire avant d'envoyer de l'argent.\n"
            "3. Activez les notifications SMS pour chaque transaction.\n"
            "4. Ne cliquez jamais sur des liens reçus par SMS vous demandant de confirmer un paiement.\n"
            "5. En cas de suspicion de fraude, contactez immédiatement votre opérateur (Orange, MTN, etc.)."
        ),
        "target_roles": "citizen",
        "display_order": 1,
        "questions": [
            {
                "text": "Que devez-vous faire si vous recevez un SMS vous demandant de confirmer un paiement via un lien ?",
                "choices": [
                    {"text": "Cliquer sur le lien pour vérifier", "is_correct": False},
                    {"text": "Ne pas cliquer et contacter votre opérateur", "is_correct": True},
                    {"text": "Ignorer complètement le message", "is_correct": False},
                    {"text": "Transmettre le lien à un ami pour avis", "is_correct": False},
                ],
            },
            {
                "text": "Quelle est une bonne pratique pour sécuriser son compte Mobile Money ?",
                "choices": [
                    {"text": "Partager son code PIN avec un membre de la famille", "is_correct": False},
                    {"text": "Activer les notifications SMS", "is_correct": True},
                    {"text": "Envoyer de l'argent sans vérifier le nom", "is_correct": False},
                    {"text": "Utiliser le même mot de passe pour tous ses comptes", "is_correct": False},
                ],
            },
            {
                "text": "Que faire en cas de transaction suspecte sur votre compte Mobile Money ?",
                "choices": [
                    {"text": "Attendre que l'argent revienne tout seul", "is_correct": False},
                    {"text": "Contacter immédiatement l'opérateur", "is_correct": True},
                    {"text": "Poster sur les réseaux sociaux", "is_correct": False},
                    {"text": "Rien, ça arrive souvent", "is_correct": False},
                ],
            },
        ],
    },
    {
        "title": "Détection des arnaques téléphoniques",
        "description": "Reconnaître et éviter les appels frauduleux fréquents au Cameroun.",
        "content": (
            "1. Méfiez-vous des appels vous annonçant un gain à un concours auquel vous n'avez pas participé.\n"
            "2. Ne fournissez jamais vos coordonnées bancaires par téléphone.\n"
            "3. Les arnaqueurs se font souvent passer pour des agents de la DGI, de la CNPS ou des opérateurs.\n"
            "4. Racrochez et rappelez le numéro officiel de l'organisme pour vérifier.\n"
            "5. Signalez les appels suspects à votre opérateur ou à la police."
        ),
        "target_roles": "citizen",
        "display_order": 2,
        "questions": [
            {
                "text": "Que faire si vous recevez un appel vous annonçant que vous avez gagné une voiture ?",
                "choices": [
                    {"text": "Donner vos coordonnées pour recevoir le prix", "is_correct": False},
                    {"text": "Raccrocher et ne pas donner d'informations", "is_correct": True},
                    {"text": "Partager l'information sur WhatsApp", "is_correct": False},
                    {"text": "Envoyer de l'argent pour les frais de dossier", "is_correct": False},
                ],
            },
            {
                "text": "Qui peut vous demander vos coordonnées bancaires par téléphone ?",
                "choices": [
                    {"text": "Un agent de la DGI", "is_correct": False},
                    {"text": "Un conseiller bancaire", "is_correct": False},
                    {"text": "Personne de confiance ne le fera par téléphone", "is_correct": True},
                    {"text": "Un opérateur Mobile Money", "is_correct": False},
                ],
            },
            {
                "text": "Comment vérifier la légitimité d'un appel d'un organisme officiel ?",
                "choices": [
                    {"text": "Rappeler le numéro qui vous a appelé", "is_correct": False},
                    {"text": "Chercher le numéro officiel sur internet et rappeler", "is_correct": True},
                    {"text": "Faire confiance à l'appelant", "is_correct": False},
                    {"text": "Transmettre l'appel à un ami", "is_correct": False},
                ],
            },
        ],
    },
    {
        "title": "Phishing et emails frauduleux",
        "description": "Apprenez à repérer les emails piégés et à protéger vos comptes.",
        "content": (
            "1. Méfiez-vous des emails qui vous demandent des informations personnelles.\n"
            "2. Vérifiez l'adresse de l'expéditeur (souvent une contrefaçon).\n"
            "3. Les liens suspects sont souvent raccourcis ou orthographiés bizarrement.\n"
            "4. Les offres trop belles pour être vraies sont généralement des pièges.\n"
            "5. En cas de doute, contactez directement l'entreprise concernée par un autre moyen."
        ),
        "target_roles": "both",
        "display_order": 3,
        "questions": [
            {
                "text": "Que faire si vous recevez un email vous demandant de mettre à jour vos identifiants bancaires ?",
                "choices": [
                    {"text": "Cliquer sur le lien et suivre les instructions", "is_correct": False},
                    {"text": "Vérifier l'adresse de l'expéditeur et contacter la banque directement", "is_correct": True},
                    {"text": "Ignorer l'email", "is_correct": False},
                    {"text": "Répondre à l'email avec vos identifiants", "is_correct": False},
                ],
            },
            {
                "text": "Comment reconnaître un lien frauduleux ?",
                "choices": [
                    {"text": "Il commence toujours par 'https'", "is_correct": False},
                    {"text": "Il contient des fautes d'orthographe ou des caractères bizarres", "is_correct": True},
                    {"text": "Il est très court", "is_correct": False},
                    {"text": "Il renvoie vers un site connu", "is_correct": False},
                ],
            },
            {
                "text": "Quelle est la meilleure réaction face à une offre alléchante reçue par email ?",
                "choices": [
                    {"text": "Saisir l'opportunité rapidement", "is_correct": False},
                    {"text": "Partager l'offre avec ses amis", "is_correct": False},
                    {"text": "Se méfier et vérifier la source", "is_correct": True},
                    {"text": "Cliquer sur le lien pour voir", "is_correct": False},
                ],
            },
        ],
    },
    {
        "title": "Protection des données personnelles",
        "description": "Comment protéger vos données sensibles dans un monde connecté.",
        "content": (
            "1. Utilisez des mots de passe forts et différents pour chaque compte.\n"
            "2. Activez la double authentification (2FA) partout où c'est possible.\n"
            "3. Méfiez-vous des applications qui demandent trop d'autorisations.\n"
            "4. Ne publiez pas vos documents d'identité sur les réseaux sociaux.\n"
            "5. Vérifiez régulièrement les paramètres de confidentialité de vos comptes."
        ),
        "target_roles": "both",
        "display_order": 4,
        "questions": [
            {
                "text": "Quelle est une pratique recommandée pour la gestion de vos mots de passe ?",
                "choices": [
                    {"text": "Utiliser le même mot de passe partout", "is_correct": False},
                    {"text": "Les écrire sur un post-it collé sur l'écran", "is_correct": False},
                    {"text": "Utiliser un gestionnaire de mots de passe", "is_correct": True},
                    {"text": "Les partager avec vos collègues", "is_correct": False},
                ],
            },
            {
                "text": "Que signifie la double authentification (2FA) ?",
                "choices": [
                    {"text": "Avoir deux mots de passe", "is_correct": False},
                    {"text": "Utiliser un code supplémentaire envoyé par SMS ou application", "is_correct": True},
                    {"text": "Se connecter avec deux comptes", "is_correct": False},
                    {"text": "Utiliser un scanner d'empreintes", "is_correct": False},
                ],
            },
            {
                "text": "Quel type d'information ne devriez-vous jamais partager sur les réseaux sociaux ?",
                "choices": [
                    {"text": "Votre ville de résidence", "is_correct": False},
                    {"text": "Votre numéro de carte d'identité", "is_correct": True},
                    {"text": "Votre passion pour le football", "is_correct": False},
                    {"text": "Votre plat préféré", "is_correct": False},
                ],
            },
        ],
    },
    {
        "title": "Faux recrutements et arnaques à l'emploi",
        "description": "Comment identifier les offres d'emploi frauduleuses et protéger votre entreprise.",
        "content": (
            "1. Méfiez-vous des offres d'emploi trop alléchantes (salaire élevé, peu d'exigences).\n"
            "2. Vérifiez toujours l'existence de l'entreprise sur Internet.\n"
            "3. Ne versez jamais d'argent pour postuler à un emploi.\n"
            "4. Les entretiens uniquement par chat ou WhatsApp sont suspects.\n"
            "5. Si l'offre demande des informations bancaires, fuyez."
        ),
        "target_roles": "company",
        "display_order": 5,
        "questions": [
            {
                "text": "Que faire si une offre d'emploi vous demande de payer des frais de dossier ?",
                "choices": [
                    {"text": "Payer car c'est normal", "is_correct": False},
                    {"text": "Ignorer l'offre, c'est une arnaque", "is_correct": True},
                    {"text": "Négocier le montant", "is_correct": False},
                    {"text": "Partager l'offre avec des amis", "is_correct": False},
                ],
            },
            {
                "text": "Comment vérifier la crédibilité d'une entreprise qui recrute ?",
                "choices": [
                    {"text": "Regarder ses réseaux sociaux uniquement", "is_correct": False},
                    {"text": "Consulter son site web et des avis en ligne", "is_correct": True},
                    {"text": "Demander à un ami", "is_correct": False},
                    {"text": "Envoyer un email à l'entreprise", "is_correct": False},
                ],
            },
            {
                "text": "Quel signal doit vous alerter lors d'un processus de recrutement ?",
                "choices": [
                    {"text": "Un entretien en visioconférence", "is_correct": False},
                    {"text": "Une demande de RIB ou de numéro de carte bancaire", "is_correct": True},
                    {"text": "Un test technique", "is_correct": False},
                    {"text": "Une proposition de contrat", "is_correct": False},
                ],
            },
        ],
    },
    {
        "title": "Sécurité des paiements en ligne pour les entreprises",
        "description": "Sécuriser les transactions et paiements B2B au Cameroun.",
        "content": (
            "1. Utilisez des passerelles de paiement sécurisées et certifiées.\n"
            "2. Formez vos employés à reconnaître les tentatives de fraude.\n"
            "3. Mettez en place des limites de transaction et des validations internes.\n"
            "4. Effectuez des audits réguliers de vos systèmes de paiement.\n"
            "5. En cas d'incident, contactez immédiatement votre banque et les autorités."
        ),
        "target_roles": "company",
        "display_order": 6,
        "questions": [
            {
                "text": "Quelle est la première mesure à prendre pour sécuriser les paiements en ligne ?",
                "choices": [
                    {"text": "Utiliser un mot de passe simple", "is_correct": False},
                    {"text": "Utiliser une passerelle de paiement sécurisée avec 3D Secure", "is_correct": True},
                    {"text": "Envoyer les transactions par email", "is_correct": False},
                    {"text": "Ne pas vérifier les transactions", "is_correct": False},
                ],
            },
            {
                "text": "Que devez-vous faire si un employé reçoit un email frauduleux demandant un virement ?",
                "choices": [
                    {"text": "Suivre les instructions de l'email", "is_correct": False},
                    {"text": "Ignorer l'email", "is_correct": False},
                    {"text": "Vérifier auprès du responsable financier avant toute action", "is_correct": True},
                    {"text": "Transmettre l'email au service informatique", "is_correct": False},
                ],
            },
            {
                "text": "Pourquoi est-il important d'effectuer des audits réguliers des systèmes de paiement ?",
                "choices": [
                    {"text": "Pour dépenser de l'argent", "is_correct": False},
                    {"text": "Pour identifier et corriger les failles de sécurité", "is_correct": True},
                    {"text": "Pour faire plaisir aux auditeurs", "is_correct": False},
                    {"text": "Pour augmenter les frais bancaires", "is_correct": False},
                ],
            },
        ],
    },
]


def seed():
    """
    Seed academy database with default modules.
    """

    Base.metadata.create_all(bind=engine)

    db = SessionLocal()

    try:
        for module_data in MODULES_DATA:

            # Check if module already exists
            module = (
                db.query(Module)
                .filter(
                    Module.title == module_data["title"]
                )
                .first()
            )

            # Update existing module
            if module:

                module.description = module_data["description"]

                module.content = module_data["content"]

                module.target_roles = TargetRole(
                    module_data["target_roles"]
                )

                module.display_order = module_data[
                    "display_order"
                ]

                # Delete old questions
                for question in list(module.questions):
                    db.delete(question)

                db.flush()

                print(
                    f"Module updated: {module.title}"
                )

            # Create new module
            else:

                module = Module(
                    title=module_data["title"],
                    description=module_data["description"],
                    content=module_data["content"],
                    target_roles=TargetRole(
                        module_data["target_roles"]
                    ),
                    display_order=module_data[
                        "display_order"
                    ],
                )

                db.add(module)
                db.flush()

                print(
                    f"Module created: {module.title}"
                )

            # Create questions
            for q_index, q_data in enumerate(
                module_data["questions"]
            ):

                question = Question(
                    module_id=module.id,
                    text=q_data["text"],
                    display_order=q_index + 1,
                )

                db.add(question)
                db.flush()

                # Create choices
                for choice_data in q_data["choices"]:

                    choice = Choice(
                        question_id=question.id,
                        text=choice_data["text"],
                        is_correct=choice_data[
                            "is_correct"
                        ],
                    )

                    db.add(choice)

        db.commit()

        print("\nSeed completed successfully")
        print(
            f"Modules: "
            f"{db.query(Module).count()}"
        )
        print(
            f"Questions: "
            f"{db.query(Question).count()}"
        )
        print(
            f"Choices: "
            f"{db.query(Choice).count()}"
        )

    except Exception as exc:

        db.rollback()

        print(f"Seed failed: {exc}")

        raise

    finally:
        db.close()

if __name__ == "__main__":
    print("Chargement des modules Academy...")
    seed()
