# LEARN — comprendre le projet m365-security-audit

Ce document explique, en français simple, les notions Microsoft 365 / Entra ID derrière le
projet, pourquoi chaque mauvaise configuration compte pour un défenseur, et comment en
parler en entretien. Rien ici n'explique comment attaquer un tenant.

## 1. Les bases

**Tenant.** L'espace d'une organisation dans le cloud Microsoft : un annuaire (Entra ID,
ex-Azure AD), des domaines (`agrisouss.ma`, `agrisouss.onmicrosoft.com`), des licences et
des services (Exchange Online pour la messagerie, SharePoint / OneDrive pour les fichiers,
Teams). Tout ce qui touche à la sécurité se règle au niveau du tenant.

**Identités.** Les *membres* (salariés), les *invités* (comptes externes B2B, `userType =
Guest`), les comptes *synchronisés* depuis un AD local (Entra Connect) et les comptes
*cloud-only*. Les applications ont aussi une identité : le *principal de service*. Dans le
cloud, l'identité est le nouveau périmètre : il n'y a plus de pare-feu entre Internet et la
boîte mail, seulement l'authentification.

**Accès conditionnel (Conditional Access, CA).** Des règles « SI qui / quelle application /
quel client / quel risque ALORS bloquer / exiger la MFA ». Une stratégie a trois états :
*activée*, *désactivée*, *rapport seul* (elle journalise ce qu'elle aurait fait, mais ne
protège rien). Les **security defaults** sont l'alternative gratuite et figée : MFA pour
tous, blocage du legacy. On utilise l'un ou l'autre, pas les deux.

**Méthodes MFA.** De la plus faible à la plus forte : SMS / appel (SIM swapping, relais
d'hameçonnage), code OTP, Microsoft Authenticator avec correspondance de nombre, puis les
méthodes **résistantes à l'hameçonnage** : clé FIDO2, passkey, Windows Hello for Business.
Une stratégie MFA ne sert à rien si l'utilisateur n'a enregistré aucune méthode.

**Authentification héritée (legacy auth).** IMAP, POP3, SMTP AUTH, anciens clients Office,
ActiveSync basique : ces protocoles envoient un mot de passe et **ne savent pas demander la
MFA**. Dans les journaux, ils apparaissent dans `ClientAppUsed` (`IMAP4`, `Other clients`...).

**Rôles et PIM.** Global Administrator peut tout faire. Privileged Identity Management (PIM,
licence P2) rend un rôle *éligible* : on l'active pour quelques heures, avec MFA et
justification. Une attribution *active permanente* = administrateur 24 h/24. Les **comptes
break-glass** (2 comptes d'urgence cloud-only, clé FIDO2 au coffre) permettent de reprendre
la main si la MFA ou une stratégie CA bloque tout le monde ; toute connexion avec eux doit
déclencher une alerte.

**Consentement OAuth.** Une application demande des permissions (`Mail.Read`,
`Files.ReadWrite.All`...). *Délégué* = au nom d'un utilisateur ; *Application* = sans
utilisateur. Si n'importe quel utilisateur peut « Accepter », une fausse application peut
obtenir un jeton qui survit au changement de mot de passe (*consent phishing*).

**Journaux d'audit.** `SigninLogs` (connexions Entra ID, avec `ResultType`, IP, pays,
client), `AuditLogs` (changements dans l'annuaire : consentement, rôles), `OfficeActivity` /
Unified Audit Log (Exchange, SharePoint, Teams : règles de boîte, accès aux fichiers). Sans
eux, impossible d'enquêter après un incident.

**Licences P1 / P2.** Entra ID P1 (inclus dans Microsoft 365 Business Premium) : accès
conditionnel, rapports de connexion. P2 : Identity Protection (risque de connexion /
utilisateur) et PIM. Le projet en tient compte : sans P2, l'absence de stratégie de risque
n'est pas une faute de configuration mais une limite de budget.

**KQL (Kusto Query Language).** Le langage de Microsoft Sentinel et Defender. On part d'une
table et on enchaîne des opérateurs avec `|` : `where` (filtrer), `summarize ... by`
(agréger), `bin()` (fenêtres de temps), `join`, `extend` (nouvelle colonne), `project`
(choisir les colonnes). Exemple : `SigninLogs | where ResultType == "50126" | summarize
dcount(UserPrincipalName) by IPAddress`.

## 2. Ce que fait l'outil, en une phrase

Il lit un export JSON de configuration (sans secret, refusé sinon), lance 24 contrôles,
calcule un score de risque 0-100 et un plan de remédiation ; et, séparément, il lance 6
détections sur des journaux JSONL et propose la requête KQL équivalente pour un SIEM.

## 3. Pourquoi chaque mauvaise configuration compte (vue défensive)

| Mauvaise configuration | Ce qu'elle permet | Ce qu'on fait |
|---|---|---|
| Ni security defaults ni CA (CA-001) | un mot de passe hameçonné suffit pour tout compte | activer les security defaults aujourd'hui |
| MFA non imposée à tous / aux admins (CA-002/003) | prise de compte par mot de passe réutilisé | stratégie CA « tous utilisateurs + MFA », MFA forte pour les admins |
| Legacy non bloqué (CA-004) | pulvérisation de mots de passe qui contourne la MFA | stratégie CA de blocage, migrer les scanners |
| Pas de stratégie de risque avec P2 (CA-005) | les signaux d'Identity Protection ne déclenchent rien | risque élevé -> bloquer / MFA |
| Exclusions larges, rapport seul (CA-006) | fausse impression de sécurité | exclusions limitées aux break-glass |
| Trop de Global Admins, rôles permanents (PRIV-001/002) | plus de comptes dont la perte est fatale | 2-4 GA, PIM juste-à-temps |
| Admin non dédié (PRIV-003) | l'admin lit ses mails = cible d'hameçonnage ; AD local compromis = cloud compromis | compte admin cloud-only séparé |
| Pas de break-glass (PRIV-004) | blocage total du tenant en cas de panne MFA | 2 comptes d'urgence surveillés |
| Invités trop libres (ACC-001) | cartographie de l'annuaire par un externe | accès invité limité |
| Comptes inutilisés (ACC-002) | compte que personne ne surveille | désactiver après 90 j |
| SSPR faible (ACC-003) | réinitialisation par un attaquant qui contrôle l'e-mail perso | 2 méthodes, pas de questions |
| Expiration des mots de passe (ACC-004) | mots de passe prévisibles (Agadir2026!) | « jamais » **après** MFA + liste interdite |
| Pas de méthode MFA / SMS seul (ACC-005) | le premier qui tape le mot de passe enregistre SA méthode | campagne d'enregistrement Authenticator |
| Consentement utilisateur libre, apps à haut privilège, enregistrement d'apps (APP-001/002/003) | accès persistant aux mails sans MFA | consentement admin + workflow de demande |
| Transfert externe automatique (COL-001) | fuite discrète des factures (BEC) | AutoForwardingMode = Off |
| SPF/DKIM/DMARC faibles (COL-002) | usurpation de @agrisouss.ma | SPF -all, DKIM, DMARC p=reject progressif |
| Teams ouvert (COL-003) | faux « support informatique » par Teams | liste de domaines autorisés |
| Liens « Tout le monde » sans expiration (COL-004) | fichiers exposés pour toujours | expiration <= 30 j, lien par défaut « personnes spécifiques » |
| Audit unifié / audit des boîtes désactivés (LOG-001/002) | aucune enquête possible | activer, exporter vers un SIEM |

## 4. Choix techniques à savoir défendre

- **Hors ligne.** L'outil ne parle jamais à Microsoft Graph : pas de jeton, pas de risque
  de modifier le tenant, et l'export peut être relu avant d'être confié à l'auditeur.
- **Refus des secrets.** Toute clé `passwordCredentials`, `secretText`, `accessToken`...
  invalide le fichier : mieux vaut un échec bruyant qu'un secret recopié dans un rapport.
- **Les dates sont relatives à `exportedAt`**, pas à « maintenant » : un rapport est
  reproductible.
- **Une stratégie en rapport seul ne compte pas**, une stratégie conditionnée au risque
  n'est pas une MFA de base : ce sont les deux pièges les plus fréquents.
- **Score** : 40/20/10/5 par sévérité, plafond 100 par catégorie, global = moitié pire
  catégorie + moitié moyenne (même formule que mon projet Active Directory).
- **Détections** : fenêtres glissantes, une alerte par IP / utilisateur, journaux triés par
  date au chargement ; chaque règle a des « quasi-incidents » dans les données normales pour
  vérifier qu'elle ne se déclenche pas trop tôt.

## 5. Questions d'entretien (18) et réponses

1. **Différence entre security defaults et accès conditionnel ?**
   Les security defaults sont gratuits et figés (MFA pour tous, legacy bloqué). L'accès
   conditionnel (P1) est configurable : exclusions, emplacements, risque, appareils. On
   active l'un ou l'autre.

2. **Pourquoi bloquer l'authentification héritée si la MFA est déjà imposée ?**
   Parce que les protocoles hérités ne savent pas demander la MFA : un mot de passe seul
   ouvre la boîte via IMAP ou SMTP AUTH. C'est le canal classique des pulvérisations.

3. **Pourquoi une stratégie en mode rapport seul est-elle signalée ?**
   Elle journalise mais n'applique rien. C'est utile quelques jours pour tester, dangereux
   si on l'oublie : l'admin croit être protégé.

4. **Quelles méthodes MFA recommandes-tu et pourquoi pas le SMS ?**
   FIDO2, passkeys, Windows Hello : résistantes à l'hameçonnage. Le SMS est vulnérable au
   SIM swapping et au relais en temps réel. Authenticator avec correspondance de nombre est
   un bon intermédiaire.

5. **Qu'est-ce qu'un compte break-glass et comment le protéger ?**
   Deux comptes d'urgence cloud-only, Global Admin permanents, clé FIDO2 au coffre, exclus
   seulement des stratégies qui pourraient bloquer l'accès, avec une alerte sur chaque
   connexion.

6. **À quoi sert PIM ?**
   Rendre les rôles éligibles plutôt que permanents : activation limitée dans le temps, MFA,
   justification, approbation pour Global Admin. La fenêtre d'exposition chute.

7. **Combien de Global Administrators ?**
   Entre 2 et 4 selon le CIS (SCuBA tolère jusqu'à 8). Un seul = risque de blocage ; trop =
   trop de comptes dont la compromission est fatale.

8. **Qu'est-ce que le consent phishing ?**
   Faire accepter à un utilisateur une fausse application qui demande l'accès à ses mails.
   Le jeton OAuth contourne la MFA et survit au changement de mot de passe. Défense :
   consentement réservé aux admins + workflow de demande.

9. **Comment détectes-tu une pulvérisation de mots de passe ?**
   Beaucoup de comptes différents en échec (`50126`) depuis une même IP sur une courte
   fenêtre (ici >= 10 en 60 min), puis on regarde si un compte a réussi ensuite.

10. **Et la fatigue MFA ?**
    Une rafale de refus MFA (`500121`) pour un utilisateur, suivie d'une connexion réussie.
    Réponse : appeler l'utilisateur, révoquer les sessions, activer la correspondance de
    nombre.

11. **Pourquoi la détection BEC combine-t-elle deux journaux ?**
    Une connexion depuis un pays inhabituel seule = beaucoup de faux positifs (voyages,
    VPN). Une règle de transfert seule aussi. Les deux en moins de 24 h, vers un domaine
    externe, avec masquage (MarkAsRead, dossier RSS), c'est le schéma typique d'une fraude
    au virement.

12. **Faux positifs du voyage impossible ?**
    VPN d'entreprise, relais iCloud, proxy mobile, géolocalisation IP imprécise. D'où le
    seuil de distance minimale (500 km) et la sévérité moyenne.

13. **Pourquoi des requêtes KQL en plus du Python ?**
    Le Python montre la logique sur des données synthétiques ; en vrai, les journaux sont
    dans Sentinel / Defender. Les requêtes KQL sont la traduction, mais je précise qu'elles
    sont relues et **non exécutées sur un vrai tenant**.

14. **Quelles licences faut-il pour tes contrôles ?**
    P1 pour l'accès conditionnel et la dernière connexion ; P2 pour PIM et Identity
    Protection. Le contrôle des stratégies de risque n'est évalué que si P2 est présent.

15. **Comment produirait-on l'export sur un vrai tenant ?**
    Avec Microsoft Graph PowerShell en lecture seule (`Connect-MgGraph` avec
    `Policy.Read.All`, `Directory.Read.All`, `AuditLog.Read.All`...), un compte Global
    Reader, uniquement sur son propre tenant ou avec autorisation écrite. Le script est
    vérifié syntaxiquement, pas testé en réel.

16. **Pourquoi déconseiller l'expiration des mots de passe ?**
    Les changements forcés produisent des mots de passe prévisibles. NIST SP 800-63B
    (rév. 4, 2025) va jusqu'à l'interdire (« SHALL NOT »), mais exige en échange une liste
    de mots de passe interdits / divulgués et un changement forcé en cas de preuve de
    fuite. Microsoft fait la même recommandation, avec la MFA imposée. Je ne passe donc à
    « jamais » qu'après la MFA et la protection par mot de passe.

17. **Comment as-tu testé l'outil ?**
    159 tests : chaque contrôle se déclenche sur l'export vulnérable et reste muet sur
    l'export durci, une seule modification d'un export propre déclenche le bon contrôle,
    limites de chaque seuil, détections avec quasi-incidents, fenêtres de temps (60 min,
    24 h) et référence de pays par utilisateur, scores, refus des secrets, échappement HTML,
    et un test qui vérifie que le script d'export n'appelle aucune cmdlet de modification.
    J'ai aussi fait des mutations à la main (changer un seuil, retirer une condition) pour
    vérifier que les tests échouent ; une revue en a trouvé qui passaient, d'où 11 tests
    ajoutés.

18. **As-tu fait ce projet seul et l'as-tu lancé sur une vraie entreprise ?**
    Je l'ai construit avec l'aide de l'IA, sur des données synthétiques d'une PME fictive.
    Il n'a jamais été exécuté sur un vrai tenant. J'ai relu le code, lancé les tests,
    vérifié les identifiants ATT&CK et les références ; je peux expliquer chaque contrôle et
    chaque détection, et je préfère le dire honnêtement.

## 6. Ligne de CV (honnête)

> Développement d'un outil Python d'audit hors ligne de la configuration Microsoft 365 /
> Entra ID (24 contrôles inspirés du CIS et de CISA SCuBA, score de risque, plan de
> remédiation) et de 6 détections sur journaux de connexion et d'audit mappées MITRE ATT&CK
> avec requêtes KQL, validé sur des **données synthétiques** (159 tests).

## 7. À ne jamais dire

- « J'ai audité le tenant Microsoft 365 d'une entreprise. » (faux : données synthétiques)
- « Mes requêtes KQL tournent dans Sentinel. » (relues, jamais exécutées)
- « Mon outil remplace Microsoft Secure Score / ScubaGear. » (il en couvre une petite partie)
