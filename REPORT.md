# Lot b2b-l14-nomem - contexte B2B explicitement sans memoire

## Livraison

- Depot : `kotnisofiane-bit/hermes-agent`.
- Base : `71b87d463e5b88ed76d70fb5edea961d06c07e4d` (`main`).
- Branche : `feat/b2b-context-no-memory`, PR unique https://github.com/kotnisofiane-bit/hermes-agent/pull/13 vers `main`, sans fusion.
- Decision produit du 16 novembre 2026 : premier parcours sans memoire ni RAG.
- Inventaire prealable fichier:ligne et historique de verification : `NOTES.md`.

Le catalogue operateur accepte desormais `memory_mode: none` en plus du mode
historique `required`. La capacite fige ce choix ; l'agent et le modele ne le
selectionnent pas. Une cle absente conserve exactement le comportement et les
empreintes historiques ; aucune absence ou panne memoire n'active le mode `none`.
Une valeur explicite entre dans l'empreinte de politique et son changement
revoque la capacite en cours.

## Contrat et fermeture

- Variante hote versionnee : `dubsar.agent-context/2.r2.no-memory/1`, champ
  obligatoire `memory_mode: "none"`. Ce n'est pas une simple absence de donnees.
- Aucun bloc `memory` ni `accepted_context` resolu via memoire : meme `null` ou
  `{}` est refuse. Aucun namespace recherche/refuse ; couverture My Work + OC
  seulement ; compteur de relations strictement nul.
- Les quatre schemas Contracts sont toujours verifies octet par octet. Seule une
  nouvelle analyse locale du schema principal est specialisee pour cette
  variante ; les blobs epingles et le contrat r2 historique restent inchanges.
- Les controles d'identite, d'autorite My Work, d'OC natif, de fraicheur, de taille,
  d'empreinte et de relecture restent actifs. Le mode figure dans les preuves et
  la comparaison de sources ; il n'est pas neutralise comme une date de lecture.
- Aucun lecteur memoire, client memoire ou service RAG n'est ajoute. La
  construction B2B conserve `skip_memory=True`, `memory_manager=None` et aucun
  outil. Le chemin Hermes qualifie/publication/relecture sans memoire est teste.
- Avant toute invocation en mode `none`, le callback preparateur doit annoncer
  `prepare_context.b2b_memory_modes = ("none",)`. Un ancien producteur est refuse
  avant son callback, jamais execute puis nettoye. Le retrait de cette declaration
  invalide aussi une preparation deja liee. Ce contrat concerne un producteur de
  confiance ; ce n'est pas une sandbox contre du Python arbitraire.
- Refus types ajoutes : `context_memory_mode`, `context_memory_unexpected`, tous
  deux classes durablement `context_stale`. En mode avec memoire, une liste vide
  reste `context_memory_missing` ; un bloc absent ne qualifie toujours pas.

## RED / GREEN et suites

Les commandes completes et journaux sont repertories dans `NOTES.md`.
Tous les tests pytest passent par `scripts/run_tests.sh` avec
`TMPDIR=/srv/dubsar-lots/b2b-l14-nomem/tmp` et `--file-retries 0`.
Les journaux bruts restent dans le dossier du lot `../evidence/`.

| Verification | Resultat | Journal |
| --- | --- | --- |
| Nouveaux invariants ecrits avant production, filtre `no_memory or memory_mode` | RED : 17 echecs fonctionnels | `../evidence/red.log` |
| Meme commande apres implementation | GREEN : 17 reussis | `../evidence/green.log` |
| Suites ciblees, 8 fichiers de tests + repertoire natif demande | 549 reussis, 0 echec | `../evidence/final_unit.log` |
| Complements de preuve apres revue, 2 fichiers complets | 108 reussis, 0 echec | `../evidence/review_checks.log` |
| Revue : mutateurs directement dans pytest.param, 2 fichiers complets | 108 reussis, 0 echec | `../evidence/review_table_checks.log` |
| Integration native avant provisionnement (historique) | 9 ignores : runtime My Work non provisionne | `../evidence/native_integration.log` |
| Integration native apres provisionnement isole | 9 reussis, 0 echec, 0 ignore | `../evidence/native_provisioned.log` |
| `git diff --check` | propre | controle final de la passe de revue |

Les 108 tests sont une reexecution des deux fichiers renforces, pas 108 tests
supplementaires a additionner aux 549. Les complements ne modifient pas le code
de production deja couvert par les suites.

La reprise de revue remplace uniquement le dispatch par nom des mutations par
une table de mutateurs callables, conforme a `AGENTS.md:252-253`. Les 108 tests
des deux fichiers ont ete rejoues avec succes, invariants inchanges. Le retour
inline 4604053935 est traite sur la meme PR. Aucune modification de production
n'intervient dans cette reprise ; les suites deja vertes restent applicables.

Le runtime natif est maintenant provisionne dans `../native-runtime/` : My Work
`526f2c76`, Contracts `9044b1b1`, dependances aux pins de `deps.lock.json`, profil
source clean `05d7394c78f9761f1d4c6f2d4805e6e9a0042e18`, Node24 et PostgreSQL16.10.
Les 9 cas natifs ont tous ete executes avec succes, sans skip, sur une instance
jetable du lot a `127.0.0.1:25432`, sans service partage ni Docker. Un premier
amorcage avait echoue faute du module `pg` ; l'installation verrouillee des
dependances du runtime resout ce blocage, sans changement des tests ni des pins.
PostgreSQL est arrete proprement apres verification ; les donnees et journaux
restent dans le lot. Ce parcours natif teste le producteur historique : il ne
livre pas le producteur natif `none`, qui reste hors perimetre.

Couverture : `tests/agent/test_b2b_execution.py`, nouveau
`tests/gateway/test_api_server_b2b_memory_mode.py`, suites existantes timeout,
execution_lane, terminal, context_capacity, oc_deadline et native profile fixture.
Le repertoire `tests/gateway/native_b2b` contient des aides et non des tests
collectables autonomes ; il a ete inclus dans la commande demandee. Ses tests
sont `test_native_b2b_profile_fixture.py` et l'integration
`test_api_server_b2b_native.py`.

Les invariants nouveaux couvrent : qualification d'une mission sans memoire,
refus d'un bloc present meme nul, refus de mode implicite ou croise, maintien du
refus de liste vide avec memoire, empreintes et revocation, publication/relecture,
verification des preuves, schema ferme et pins intacts, ancien producteur non
invoque, retrait d'opt-in et types JSON malformes. Des tripwires installes apres
la vraie decouverte du plugin observent zero appel au store memoire, au prefetch,
a urllib et a socket.connect pendant la preparation et ses validateurs avec le
producteur DOUBLE. Ce n'est pas une preuve du futur producteur externe.

## Hors perimetre et limites

- Le hook `prepare_context` du depot `dubsar-hermes-profile` appartient a un lot
  separe : aucune modification de ce depot ni du patch de test natif versionne.
  Profil consulte en lecture seule a `05d7394c78f9761f1d4c6f2d4805e6e9a0042e18`.
- Le lecteur My Work B2B appartient a un lot separe : aucune implementation ici.
- Le producteur natif `none` n'est pas livre dans cette PR. Le profil actuel
  n'enregistre pas le hook de preparation ; le chemin installe reste ferme.
- Les 9 cas natifs passent apres provisionnement de `B2B_TEST_MY_WORK_ROOT` dans
  le lot ; le skip initial est conserve comme historique, pas comme resultat
  final. Aucun E2E natif `none` n'est revendique : seul le producteur historique
  est disponible dans le fixture epingle. Aucune source partagee modifiee.
- Aucun deploiement, modele reel, parcours navigateur Portal, affichage approbateur
  ou qualification de l'isolation reseau n'est revendique.
- Aucun changement de `.github/workflows/`, aucun Docker/sudo, aucun nettoyage de
  cache ; les temporaires restent dans le lot. Aucun nouveau port applicatif.

## Vision

Controle effectue avant push. Une ligne par principe touche ; aucun ecart nouveau
non justifie. Les ecarts systemiques de la grille initiale ne sont pas declares
resolus par ce lot.

| # | Verdict | Preuve fichier:ligne et limite |
| --- | --- | --- |
| 1 | respecte | `gateway/platforms/api_server_b2b_execution.py:331-350` : un tour, aucun outil, aucune memoire native ; le contexte ne donne pas d'autorite d'action. |
| 3 | respecte | `gateway/platforms/api_server_b2b_execution.py:336-350` : aucun outil ni acces metier ajoute ; `gateway/platforms/api_server_b2b_context.py:157-182` refuse un ancien producteur avant invocation, sans nouveau client externe. |
| 4 | respecte | `agent/b2b_execution.py:151-166,258-278` : le mode reste dans la base comparee ; `gateway/platforms/api_server_b2b.py:734-735` l'inclut dans la politique ; `gateway/platforms/api_server_b2b_context.py:217-234` conserve la fenetre OC. Aucune qualification de l'approbation Core ajoutee. |
| 5 | respecte | `agent/b2b_execution.py:242-290,705-750` : empreintes et controle du mode dans les preuves ; `gateway/platforms/api_server_b2b.py:817-818,1088-1111` : refus classes et contexte exact persiste. |
| 6 | respecte | `tests/agent/test_b2b_execution.py:611-625` : rendu exact et mode conserves dans le recu publie ; `gateway/platforms/api_server_b2b.py:1102-1106` conserve vue et rendu. Aucune nouvelle vue approbateur ni affichage modele/tokens revendique. |
| 9 | respecte | `gateway/platforms/api_server_b2b_execution.py:331-350` : meme modele/provider/base_url du catalogue et aucune passerelle alternative ajoutee. |
| 10 | respecte dans le perimetre Hermes | `agent/b2b_execution.py:713-735,800-806` : absence totale des blocs memoire et correspondance avec le choix operateur ; `tests/gateway/test_api_server_b2b_memory_mode.py:139-152,192` : zero E/S memoire/reseau du chemin teste. Pas de preuve de sandbox, du futur plugin externe ni de fermeture reseau de production. |
| 11 | respecte | `website/docs/developer-guide/b2b-c1-producer-contract.md:252-308` : contrat, responsabilites et limites explicites ; RED/GREEN, suites et skips distingues dans ce rapport, aucune revendication de deploiement. |

Les principes 2, 7, 8, 12, 13 et 14 n'ont pas de surface modifiee : approbation
humaine, arret global, couts, Portal, precedence documentaire et mesure continue
des propositions restent leurs lots respectifs. Aucun etat global de ces lignes
n'est avance dans la grille produit.

## Cloture

Revue du diff, traitement du retour inline et controle Vision acceptes.
`origin/main` reste au SHA de base au dernier controle. Les suites locales
requises sont executees, y compris 9/9 cas natifs sans skip. La CI distante
comporte encore des jobs en attente au dernier controle : aucune CI globale
verte n'est revendiquee.

`NOTES.md` est tenu ; ce rapport est la derniere modification de fichier du lot,
apres implementation, tests, revue et arret du runtime. Les operations restantes
sont le commit et le push du correctif puis l'actualisation de la PR13 existante ;
aucune nouvelle PR, fusion ni mise en production.
