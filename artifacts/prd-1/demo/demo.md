# Démo — PRD #1, plateforme de gouvernance des images

Enregistrée sur la plateforme `harborlab` reconstruite de zéro (`task down && task up`), les 20 Applications Argo CD Synced/Healthy.
Les interfaces web sont capturées à 1280×800 : Harbor, Dependency-Track, Grafana et Policy Reporter sont des consoles de poste de travail (voir « Écarts » en fin de page).
Les connexions se font hors champ : aucune image ne montre de formulaire de connexion rempli ni de secret.

**Avant :** non capturé pour tous les écrans — `main` ne contient que le PRD : aucun de ces écrans n'existe avant cette branche.

### P1 — Voir la plateforme refuser une image non conforme
Critères : 9, 10, 11, 23
Départ : plateforme démarrée (`task up` terminé), terminal à la racine du dépôt

Enregistrement complet : [P1.mp4](./artifacts/prd-1/demo/P1.mp4) (terminal 68×16, source [P1.cast](./artifacts/prd-1/demo/P1.cast)).

**1. Lance `task demo:unsigned` — l'admission refuse le pod : image non signée**

![P1-01](./artifacts/prd-1/demo/P1-01.png)

**2. Lance `task demo:foreign-signer` — refus : signature d'une autre identité que le workflow du dépôt**

![P1-02](./artifacts/prd-1/demo/P1-02.png)

**3. Lance `task demo:direct-dockerhub` — refus : image hors des projets Harbor `golden`/`apps`**

![P1-03](./artifacts/prd-1/demo/P1-03.png)

**4. Lance `task demo:non-golden-base` — refus : base absente du catalogue**

![P1-04](./artifacts/prd-1/demo/P1-04.png)

**5. Lance `task demo:eol-base` — refus : base golden en fin de vie**

![P1-05](./artifacts/prd-1/demo/P1-05.png)

**6. Lance `task demo:root` — refus : le pod viole Pod Security `restricted`**

![P1-06](./artifacts/prd-1/demo/P1-06.png)

**7. Lance `task demo:deprecated-base` — le pod est admis, l'avertissement de dépréciation s'affiche**

![P1-07](./artifacts/prd-1/demo/P1-07.png)

**8. Affiche l'image du pod admis — la référence est en digest `@sha256:`**

Saisi : `kubectl -n runtime-demo get pod demo-deprecated-base -o jsonpath='{.spec.containers[0].image}{"\n"}'`

![P1-08](./artifacts/prd-1/demo/P1-08.png)

Écran final :

![P1-fin](./artifacts/prd-1/demo/P1-fin.png)

### P2 — Suivre une image du golden path jusqu'au tri des CVE
Critères : 6, 15, 16, 17
Départ : plateforme démarrée, `dt-bridge` et `hello-java` déployés, navigateur ouvert sur Harbor avec le compte admin seedé

**1. Ouvre le projet Harbor `golden` — les images python et java sont présentes, tags immuables**

![P2-01](./artifacts/prd-1/demo/P2-01.png)

Le projet liste `golden/java` et `golden/python` ; l'utilisateur ouvre l'onglet Policy, puis Tag immutability.

![P2-01b](./artifacts/prd-1/demo/P2-01b.png)
![P2-01c](./artifacts/prd-1/demo/P2-01c.png)
![P2-01d](./artifacts/prd-1/demo/P2-01d.png)

**2. Ouvre le projet `apps`, puis le dépôt `hello-java`**

![P2-02](./artifacts/prd-1/demo/P2-02.png)
![P2-02b](./artifacts/prd-1/demo/P2-02b.png)

**3. Ouvre l'artefact — la signature, les SBOM et la provenance apparaissent comme accessoires**

![P2-03](./artifacts/prd-1/demo/P2-03.png)

Quatre accessoires, tous typés `signature.cosign` par Harbor ; l'utilisateur ouvre l'un d'eux pour lire son type réel.

![P2-03b](./artifacts/prd-1/demo/P2-03b.png)

L'annotation `dev.sigstore.bundle.predicateType` vaut `https://slsa.dev/provenance/v1` (les trois autres : CycloneDX, SPDX et la signature).

![P2-03c](./artifacts/prd-1/demo/P2-03c.png)

**4. Ouvre Dependency-Track, liste des projets — le projet `hello-java` porte le tag en version**

![P2-04](./artifacts/prd-1/demo/P2-04.png)

Saisi dans la recherche : `hello-java`

![P2-04b](./artifacts/prd-1/demo/P2-04b.png)

**5. Ouvre le projet — les composants viennent du SBOM attesté**

![P2-05](./artifacts/prd-1/demo/P2-05.png)
![P2-05b](./artifacts/prd-1/demo/P2-05b.png)
![P2-05c](./artifacts/prd-1/demo/P2-05c.png)

**6. Ouvre le projet `golden/python`, onglet audit des vulnérabilités — aucune CVE Debian n'est listée**

![P2-06](./artifacts/prd-1/demo/P2-06.png)

Saisi dans la recherche : `golden/python`

![P2-06b](./artifacts/prd-1/demo/P2-06b.png)
![P2-06c](./artifacts/prd-1/demo/P2-06c.png)
![P2-06d](./artifacts/prd-1/demo/P2-06d.png)

Écran final — « No matching records found » (DependencyTrack/dependency-track#6132) :

![P2-fin](./artifacts/prd-1/demo/P2-fin.png)

### P3 — Repérer un shell dans un conteneur depuis Grafana
Critères : 12, 20, 21
Départ : plateforme démarrée, `task demo:runtime-shell` lancé à 08:35:35 UTC (alerte reçue en 2 s), navigateur ouvert sur Grafana avec le compte seedé

**1. Ouvre le tableau de bord « image posture »**

![P3-01](./artifacts/prd-1/demo/P3-01.png)
![P3-01b](./artifacts/prd-1/demo/P3-01b.png)

**2. Sélectionne l'image golden python**

![P3-02](./artifacts/prd-1/demo/P3-02.png)
![P3-02b](./artifacts/prd-1/demo/P3-02b.png)

Juste après la sélection, le panneau « Runtime alerts » affiche encore « No data » (environ une minute après le shell) :

![P3-02c](./artifacts/prd-1/demo/P3-02c.png)

**3. Lit les compteurs de CVE par sévérité, avant et après VEX**

Au rafraîchissement automatique suivant (30 s) :

![P3-03](./artifacts/prd-1/demo/P3-03.png)

**4. Lit la part d'images signées et attestées en cours d'exécution**

![P3-04](./artifacts/prd-1/demo/P3-04.png)

**5. Repère l'alerte runtime du shell ouvert dans le pod ciblé**

![P3-05](./artifacts/prd-1/demo/P3-05.png)

**6. Ouvre Explore sur VictoriaLogs — l'événement Kubescape détaillé s'affiche**

![P3-06](./artifacts/prd-1/demo/P3-06.png)
![P3-06b](./artifacts/prd-1/demo/P3-06b.png)
![P3-06c](./artifacts/prd-1/demo/P3-06c.png)

Au choix de VictoriaLogs, Grafana est tué par manque de mémoire (OOMKilled, limite 448 Mi) : l'éditeur de requête ne se charge pas et la requête échoue.

![P3-06c-erreur](./artifacts/prd-1/demo/P3-06c-erreur.png)

Après le redémarrage de Grafana, l'utilisateur rouvre Explore par le lien de la requête du runbook : `RuleID:R0001 AND RuntimeK8sDetails.namespace:="runtime-demo"`

![P3-06d](./artifacts/prd-1/demo/P3-06d.png)

Détail de l'événement : `Unexpected process launched`, pod `runtime-demo-67cc7d76bf-qkhxh`.

![P3-06e](./artifacts/prd-1/demo/P3-06e.png)

**7. Ouvre Policy Reporter — les PolicyReports Kyverno sont listés, dont l'avertissement de base dépréciée et le registre hors liste en namespace plateforme**

![P3-07](./artifacts/prd-1/demo/P3-07.png)
![P3-07b](./artifacts/prd-1/demo/P3-07b.png)
![P3-07c](./artifacts/prd-1/demo/P3-07c.png)
![P3-07d](./artifacts/prd-1/demo/P3-07d.png)

Écran final — `platform-registry-allow-list` en échec sur le namespace `observability` :

![P3-fin](./artifacts/prd-1/demo/P3-fin.png)

## Écarts

- Les parcours web sont capturés à 1280×800 et non au format téléphone : à 390 px de large, Harbor superpose son menu latéral au contenu et rend les étapes illisibles.
- P3 étape 6 : l'éditeur de requête a planté au premier essai (Grafana OOMKilled) ; l'étape n'a abouti qu'au second essai, par lien direct.
