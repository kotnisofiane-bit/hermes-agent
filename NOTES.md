# Lot b2b-l14-nomem

## Cadre

- Demande produit du 16 novembre 2026 : premier parcours B2B sans memoire ni RAG.
- Depot cible : `kotnisofiane-bit/hermes-agent`, base `71b87d463e5b88ed76d70fb5edea961d06c07e4d`.
- Branche unique : `feat/b2b-context-no-memory`. Une seule PR, aucune fusion.
- Profil consulte en lecture seule : `kotnisofiane-bit/dubsar-hermes-profile`
  a `05d7394c78f9761f1d4c6f2d4805e6e9a0042e18`.
- Aucun changement de workflow, Docker, sudo ou suppression externe au lot.
  Les eventuels ports de test doivent etre >= 20000.

## Inventaire avant modification

Les references de cette section correspondent aux SHA de base ci-dessus.

### Qualification et preuves Hermes

- `agent/b2b_execution.py:298-333` : charge quatre schemas Contracts epingles
  (`R2_SCHEMA_PINS`, lignes 68-77), validation fermee et resolution sans reseau.
  Le schema r2 impose `memory` ; une simple absence ne peut donc pas qualifier.
- `agent/b2b_execution.py:675-731` : `qualify_recorded_memory` exige les constantes
  advisory, une liaison mission, des namespaces recherches non vides, une source
  disponible et fraiche, l'API v2, aucune limite/troncature/repli, des relations
  non vides, une qualification mission et des contradictions propagees resolues.
  `context_memory_malformed` aux lignes 689-693 et 707-708 ;
  `context_memory_missing` aux lignes 709-710.
- `agent/b2b_execution.py:660-672` : namespace et provenance de chaque relation.
- `agent/b2b_execution.py:734-830` : `qualify_context_view` qualifie schema,
  empreinte, identites, autorite My Work, sources et OC. Extraction obligatoire
  de `memory` ligne 774 et appel inconditionnel ligne 792. Les relations
  `accepted_context.target` et `memory_supports` sont aussi qualifiees et comptees
  aux lignes 805-824.
- `agent/b2b_execution.py:272-281` : `verify_context_proof` requalifie la memoire
  apres recalcul des preuves ; ce chemin durable doit aussi comprendre le mode.
- `agent/b2b_execution.py:150-165,233-269` : base semantique et preuves de contexte ;
  seules les metadonnees de lecture OC sont neutralisees pour comparer les sources.
- `gateway/platforms/api_server_run_idempotency.py:466-473,554-561` : verification
  commune des preuves avant dispatch et scellement durables.
- `gateway/platforms/api_server_b2b.py:88-92,264-322,694-730` : catalogue ferme
  operateur, normalisation et empreinte de politique. Le choix du mode doit
  provenir de ce catalogue et revoquer l'execution s'il change.
- `gateway/platforms/api_server_b2b_execution.py:348-350` : construction B2B avec
  `memory_manager=None`, `skip_memory=True`, `skip_context_files=True` ; aucun
  nouveau lecteur de memoire natif Hermes n'est necessaire.
- `agent/b2b_execution.py:400-440` et
  `gateway/platforms/api_server_b2b.py:798-825` : vocabulaire ferme des refus et
  classification durable a maintenir ensemble.

### Producteur externe et hook

- `gateway/platforms/api_server_b2b_context.py:42-61` : introspection d'un seul
  callback `prepare_context` enregistre par un plugin qui possede aussi
  `pre_llm_call` ; ne declenche pas la decouverte.
- `gateway/platforms/api_server_b2b_context.py:157-169,302-361` : invoque le
  producteur avec la capacite hote, qualifie sa vue et son rendu, impose une
  preuve OC native courante, lie la preparation a cette capacite.
- Profil, `plugins/dubsar-agent-context/dubsar_agent_context/plugin.py:85-100` :
  publication via `pre_llm_call` et `bound_context`. Le SHA consulte
  n'enregistre PAS `prepare_context`.
- Profil, `plugins/dubsar-agent-context/dubsar_agent_context/b2b_runtime.py:76-142` :
  composition des ports lies au catalogue ; impose actuellement un client
  Memory Plane v2. Lignes 180-197 : relecture et publication via le builder v2.
- Profil, `plugins/dubsar-agent-context/dubsar_agent_context/assembly_v2.py:284-310` :
  `_read_memory` appelle `qualified_context_view` pour chaque namespace.
  Lignes 588-603 : appel inconditionnel et resolution des supports de contexte
  accepte avec `hook.memory`. Lignes 619-634 : produit le bloc `memory`.
- Profil, `plugins/dubsar-agent-context/dubsar_agent_context/memory_v2.py:211-240` :
  construit puis transmet le verbe prive `qualified-context-view`.
- `tests/gateway/native_b2b/profile_fixture.py:18-20,45-72` et
  `tests/gateway/native_b2b/dubsar-hermes-profile-prepare-context.patch:20-46,66-69` :
  le parcours natif materialise une copie du profil avec un patch de test
  versionne pour `prepare_context`. Ce n'est pas une livraison du hook externe.

### Tests existants

- `tests/agent/test_b2b_execution.py:518-543` : qualification complete et verification
  de preuve persistante sur les vrais schemas epingles ; fraicheur memoire.
- `tests/agent/test_b2b_execution.py:217-239,269-291,310-372` : empreintes,
  derive des sources, relectures OC, publication et requalification.
- `tests/gateway/b2b_process_harness.py:157-270` : producteur explicitement DOUBLE,
  construit toujours une relation memoire synthetique non vide.
- `tests/gateway/test_api_server_b2b_execution_lane.py:1181-1305,1339-1488,2053-2200` :
  publication par hook, disponibilite du producteur, preparation liee,
  qualification et echeances de source.
- `tests/gateway/test_api_server_b2b_context_capacity.py:65-154` : doubles de
  producteurs et validateurs pour les echeances des workers de preparation.
- `tests/gateway/test_api_server_b2b_native.py:424-528` : parcours natif,
  isolation A-B-A, rejeu, refus memoire absente/perimee/croisee/tardive.
  Les services Memory Plane et modele restent des doubles HTTP.
- `tests/gateway/test_api_server_b2b_timeout.py:37-145,233-295` : modele existant
  pour catalogue optionnel, conservation des empreintes historiques et revocation.
- Profil, `tests/persistent-agent-memory/test_agent_context_v2.py:325-336,382-428,462-477,568-635,725-773` :
  triplet mission des lectures qualifiees, refus des croisements, indisponibilite
  My Work/memoire, transport HTTP et absence de repli.

## Decisions de conception

- Catalogue operateur : `memory_mode`, valeurs fermees `required` et `none`.
  Cle absente : comportement historique `required`, sans modifier les octets
  canoniques historiques. Aucune decision dans les arguments du modele.
- Variante hote explicite : `dubsar.agent-context/2.r2.no-memory/1`,
  champ obligatoire `memory_mode: none`, aucun bloc `memory` ni bloc
  `accepted_context` resolu via memoire, aucun namespace recherche/refuse,
  aucune capacite memoire declaree, compteur de relations nul.
- Validation de cette variante par specialisation locale des memes quatre
  schemas verifies octet par octet ; aucune modification des pins Contracts.
  Le contrat r2 historique reste strictement inchange.
- Le mode doit correspondre a la politique immuable de la capacite ; format
  et mode font partie de la preuve et de la base de comparaison.
- Un producteur doit annoncer explicitement le support `none` AVANT invocation.
  Un ancien hook est refuse avant lecture, jamais execute puis nettoye.
- Hors perimetre : livraison du hook `prepare_context` dans le depot profil,
  lecteur My Work B2B, deploiement, modele reel et preuve navigateur.

## Suivi

- Inventaire termine avant implementation. `rg` absent de l'environnement ;
  recherches realisees avec `grep`/`find`, sans installation globale.
- Tests ecrits avant toute modification de production :
  `tests/agent/test_b2b_execution.py` (+103 lignes, double de vue
  `_no_memory_view` explicitement synthetique) et nouveau
  `tests/gateway/test_api_server_b2b_memory_mode.py` (catalogue, empreinte,
  revocation, opt-in producteur via vrai plugin `fake_plugin_home`).
- RED (avant production), commande exacte :
  `TMPDIR=/srv/dubsar-lots/b2b-l14-nomem/tmp scripts/run_tests.sh -j 1 --file-retries 0 tests/agent/test_b2b_execution.py tests/gateway/test_api_server_b2b_memory_mode.py -k 'no_memory or memory_mode'`
  Resultat : 17 echecs fonctionnels attendus (11 agent + 6 gateway, surtout
  `context_schema_invalid` faute de variante, plus validation catalogue
  absente). Journal : `/srv/dubsar-lots/b2b-l14-nomem/evidence/red.log`.
- Production appliquee : `agent/b2b_execution.py` (constante, helper
  `_context_memory_mode`, specialisation locale du schema fraichement parse,
  qualification et `source_basis`), `gateway/platforms/api_server_b2b.py`
  (cle catalogue `memory_mode`, validation enum, empreinte, raisons
  durables), `gateway/platforms/api_server_b2b_context.py`
  (`_assert_producer_memory_mode` avant invocation et au re-scellement du
  stamp), `website/docs/developer-guide/b2b-c1-producer-contract.md`
  (section `Explicit no-memory variant`, intro et delta Vision).
- GREEN (apres production), meme commande que RED :
  17/17 reussis en 3.5 s. Journal : `/srv/dubsar-lots/b2b-l14-nomem/evidence/green.log`.
- Suite unitaire finale, commande exacte :
  `TMPDIR=/srv/dubsar-lots/b2b-l14-nomem/tmp scripts/run_tests.sh -j 2 --file-retries 0 tests/agent/test_b2b_execution.py tests/gateway/test_api_server_b2b_memory_mode.py tests/gateway/test_api_server_b2b_timeout.py tests/gateway/test_api_server_b2b_execution_lane.py tests/gateway/test_api_server_b2b_terminal.py tests/gateway/test_api_server_b2b_context_capacity.py tests/gateway/test_api_server_b2b_oc_deadline.py tests/gateway/test_native_b2b_profile_fixture.py tests/gateway/native_b2b`
  Resultat : 8 fichiers, 549 tests reussis, 0 echec en 80.1 s.
  Journal : `/srv/dubsar-lots/b2b-l14-nomem/evidence/final_unit.log`.
- Suite native integration, commande exacte :
  `TMPDIR=/srv/dubsar-lots/b2b-l14-nomem/tmp scripts/run_tests.sh -j 1 --file-retries 0 --include-integration -m 'integration or not integration' tests/gateway/test_api_server_b2b_native.py`
  Resultat : 0 reussi, 0 echec, 9 explicites skip.
  `B2B_TEST_MY_WORK_ROOT` non provisionne dans l'environnement : les tests
  natifs skippent proprement comme prevu ; aucun PostgreSQL/My Work fabrique
  ni base partagee. Journal : `/srv/dubsar-lots/b2b-l14-nomem/evidence/native_integration.log`.
- Complements de preuve apres revue complete du diff : tests incrementaux
  seuls, aucune retouche production.
  - `test_no_memory_context_qualification_and_recorded_proof` : mutations
    `coverage_unhashable` (membre `{}` -> `context_memory_mode`, pas de
    TypeError aux deux frontieres) et `relation_count_bool`
    (`False` -> `context_relation_bounds`) ; parcours reel
    publication/relecture (`publish_context` + `recheck_context`, recu
    persiste au sink, `memory` absent, `memory_mode: none`); schema ferme
    (champ inconnu -> `context_schema_invalid`) et pin corrompu sur la copie
    propre au test -> `context_contract_unavailable`.
  - `test_no_memory_preparation_requires_explicit_producer_support` :
    tripwires installes apres `discover_plugins` pour tous les scenarios
    (`MemoryStore.load_from_disk`, `MemoryManager.prefetch_all`,
    `urllib.request.urlopen`, `socket.socket.connect`) ; `memory_io == []`
    verifie en fin de test. Invariant zero E/S du chemin Hermes avec
    producteur double, pas une preuve de sandbox du plugin externe.
    `lane.store.close()` desormais en `finally`.
  - Fingerprints catalogue : `required` != `none` verifie explicitement en
    plus de la difference avec le defaut.
  - Doc : refus `required` precises (bloc absent/malforme vs liste vide) ;
    perimetre de preuve = qualification/publication Hermes et doubles
    unitaires, aucun parcours natif E2E `none` revendique.
- Verification unique apres complements, commande exacte :
  `TMPDIR=/srv/dubsar-lots/b2b-l14-nomem/tmp scripts/run_tests.sh -j 1 --file-retries 0 tests/agent/test_b2b_execution.py tests/gateway/test_api_server_b2b_memory_mode.py`
  Resultat : 2 fichiers, 108 tests reussis, 0 echec en 13.1 s. Journal :
  `/srv/dubsar-lots/b2b-l14-nomem/evidence/review_checks.log`.
  `git diff --check` : propre.
- `NOTES.md` a inclure dans la PR (inventaire + suivi de livraison).
  Aucun commit/push.
- Limites residuelles : producteur natif `none` non livre (patch de test
  versionne inchange, lecture seule) ; parcours natif installe non qualifie
  (skip explicite ci-dessus) ; aucune avance deploiement/approbateur.
- Revue finale du diff terminee : acceptee. Controle Vision avant push :
  principes touches 1, 3, 4, 5, 6, 9, 10 et 11 respectes dans le perimetre
  Hermes ; preuves et limites detaillees dans REPORT.md. Aucun ecart nouveau
  non justifie. origin/main toujours au SHA de base (comparaison 0/0).
- Rapport final ecrit APRES les tests et la revue ; prochaine operation :
  commit/push de feat/b2b-context-no-memory puis creation d'une seule PR.
- Reprise post-review (retour inline 4604053935) :
  - `test_no_memory_context_qualification_and_recorded_proof` refactorise :
    parametres `mutate` callables + `reason` + ids pytest explicites,
    suppression du dispatch par nom (regle ladder >=4). Assertions et
    `reseal_unit_context_view` inchanges ; aucun invariant ajoute/retire.
  - Verification : `TMPDIR=/srv/dubsar-lots/b2b-l14-nomem/tmp scripts/run_tests.sh -j 1 --file-retries 0 tests/agent/test_b2b_execution.py tests/gateway/test_api_server_b2b_memory_mode.py`
    -> 108 reussis, 0 echec en 13.5 s. Journal :
    `/srv/dubsar-lots/b2b-l14-nomem/evidence/review_table_checks.log`.
- Runtime natif provisionne dans le lot (`native-runtime/`), isole :
  - `native-runtime/mywork` = dubsar-my-work @ `526f2c76`, `deps.lock.json`
    resolu par `scripts/bootstrap-deps.mjs` (sources locales) :
    `.deps/dubsar-memory` @ `c7886578`, `.deps/dubsar-contracts-*` @
    `9044b1b1`/`448c1c04`/`59e93bb9`, `npm ci --ignore-scripts` atteste pour
    `dubsar-contracts-b2b-mission-identity`. `packages/` = symlinks pins.
  - `native-runtime/contracts` = dubsar-contracts @ `9044b1b1fd38` (detache).
  - `native-runtime/sources-memory` = clone source dubsar-memory.
  - `packages/dubsar-workbench-launcher` : `npm ci --ignore-scripts` (pg 8.16.3
    via son package-lock versionne) — seule dependance JS externe du repo.
  - PostgreSQL 16.10 (`/opt/dubsar-tools/pg`) : `initdb -A trust -U lotrunner`
    dans `native-runtime/pgdata`, ecoute `127.0.0.1:25432` (>=20000), socket
    `native-runtime/pgsock`, log `native-runtime/pg.log`. Instance jetable du
    lot, aucune DB partagee : les fixtures creent/droppent leurs bases
    `p2_*`. Arret : `/opt/dubsar-tools/pg/bin/pg_ctl -D /srv/dubsar-lots/b2b-l14-nomem/native-runtime/pgdata stop`.
  - Node `/opt/dubsar-tools/node24/bin/node` v24.19.0 (binaire machine,
    lecture seule). Runtime JSON : `native-runtime/.p2-native-runtime.json`.
  - Premier essai : 9 erreurs d'amorcage kernel, `Cannot find module 'pg'`
    (dependance workbench-launcher non installee) ; correction env ci-dessus
    (un seul `npm ci` pinned), kernel verifie manuellement (ready +
    helper.sock + migrations PG).
  - Commande exacte :
    `B2B_TEST_MY_WORK_ROOT=/srv/dubsar-lots/b2b-l14-nomem/native-runtime TMPDIR=/srv/dubsar-lots/b2b-l14-nomem/tmp timeout --kill-after=10s 890s scripts/run_tests.sh -j 1 --file-retries 0 --include-integration -m 'integration or not integration' tests/gateway/test_api_server_b2b_native.py`
    -> 9 reussis, 0 echec, 0 skip en 39.4 s. Journal :
    `/srv/dubsar-lots/b2b-l14-nomem/evidence/native_provisioned.log`.
    Le parcours natif reel (kernel OC + PG + helper + producteur profile
    patche par le fixture) s'execute ; cela ne livre pas le producteur
    `none` natif, hors perimetre inchange.
- Revue du correctif de reprise terminee et acceptee : mutateurs en table,
  memes invariants, production inchangee. Retour inline 4604053935 traite ;
  reponse publiee sur la PR13 (discussion_r4604150683).
- Preuves finales : 108 tests des deux fichiers renforces reussis apres
  refactorisation ; 9 tests natifs reussis, sans skip, sur runtime isole.
  PostgreSQL du lot arrete proprement apres verification ; donnees et logs
  conserves, aucune suppression. Aucun processus du lot laisse actif.
- Controle Vision reitere avant push : principes 1/3/4/5/6/9/10/11 respectes
  dans le perimetre, citations de preuve actualisees. origin/main reste au
  SHA de base. La CI distante comporte encore des jobs en attente : seule
  la verification locale terminee est revendiquee.
- Rapport actualise en DERNIERE ecriture apres ces notes et l'arret du
  runtime. Publication du correctif sur la PR existante13, aucune nouvelle PR.
