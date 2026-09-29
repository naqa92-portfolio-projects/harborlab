# Démo — PRD #1, plateforme de gouvernance des images

Enregistrée sur la plateforme `harborlab` au commit produit `00c52d4` (les 20 Applications Argo CD Synced/Healthy), après les correctifs du script d'admission et de la limite mémoire de Grafana (768 Mi).
Les interfaces web sont capturées à 1280×800 : Harbor, Dependency-Track, Grafana et Policy Reporter sont des consoles de poste de travail (voir « Écarts » en fin de page).
Les connexions se font hors champ : aucune image ne montre de formulaire de connexion rempli ni de secret.
Sur chaque image, l'anneau rouge marque l'endroit où l'utilisateur clique ; la flèche marque un défilement.

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

La règle d'immuabilité couvre tous les dépôts, tags hors `sha256-*` ; l'utilisateur revient à la liste des projets.

![P2-01d](./artifacts/prd-1/demo/P2-01d.png)

**2. Ouvre le projet `apps`, puis le dépôt `hello-java`**

![P2-02](./artifacts/prd-1/demo/P2-02.png)
![P2-02b](./artifacts/prd-1/demo/P2-02b.png)

**3. Ouvre l'artefact — la signature, les SBOM et la provenance apparaissent comme accessoires**

![P2-03](./artifacts/prd-1/demo/P2-03.png)

Quatre accessoires, tous typés `signature.cosign` par Harbor ; l'utilisateur ouvre l'un d'eux pour lire son type réel.

![P2-03b](./artifacts/prd-1/demo/P2-03b.png)

L'annotation `dev.sigstore.bundle.predicateType` vaut `https://slsa.dev/provenance/v1`.

![P2-03c](./artifacts/prd-1/demo/P2-03c.png)

**4. Ouvre Dependency-Track, liste des projets — le projet `hello-java` porte le tag en version**

![P2-04](./artifacts/prd-1/demo/P2-04.png)

Saisi dans la recherche : `hello-java` — la version `sha-6dccb90…` est le tag de l'image dans Harbor.

![P2-04b](./artifacts/prd-1/demo/P2-04b.png)

**5. Ouvre le projet — les composants viennent du SBOM attesté**

![P2-05](./artifacts/prd-1/demo/P2-05.png)

1 312 composants, dont `/app/hello-java.jar` et le JRE ; l'utilisateur revient à la liste des projets.

![P2-05b](./artifacts/prd-1/demo/P2-05b.png)

**6. Ouvre le projet `golden/python`, onglet audit des vulnérabilités — aucune CVE Debian n'est listée**

![P2-06](./artifacts/prd-1/demo/P2-06.png)

Saisi dans la recherche : `golden/python` — l'utilisateur ouvre la version `sha-b9fdf90…` (python 3.13, supportée au catalogue).

![P2-06b](./artifacts/prd-1/demo/P2-06b.png)
![P2-06c](./artifacts/prd-1/demo/P2-06c.png)

Écran final — « No matching records found » (DependencyTrack/dependency-track#6132) :

![P2-fin](./artifacts/prd-1/demo/P2-fin.png)

### P3 — Repérer un shell dans un conteneur depuis Grafana
Critères : 12, 20, 21
Départ : plateforme démarrée, `task demo:runtime-shell` lancé à 09:40:39 UTC (alerte reçue en 3 s, pod `runtime-demo-86b997bf86-b4ss9`), navigateur ouvert sur Grafana avec le compte seedé

**1. Ouvre le tableau de bord « image posture »**

![P3-01](./artifacts/prd-1/demo/P3-01.png)
![P3-01b](./artifacts/prd-1/demo/P3-01b.png)

**2. Sélectionne l'image golden python**

Le tableau de bord s'ouvre sur `java` ; l'utilisateur choisit `python`.

![P3-02](./artifacts/prd-1/demo/P3-02.png)
![P3-02b](./artifacts/prd-1/demo/P3-02b.png)

**3. Lit les compteurs de CVE par sévérité, avant et après VEX**

![P3-03](./artifacts/prd-1/demo/P3-03.png)

**4. Lit la part d'images signées et attestées en cours d'exécution**

![P3-04](./artifacts/prd-1/demo/P3-04.png)

**5. Repère l'alerte runtime du shell ouvert dans le pod ciblé**

« Unexpected process launched » est compté dès la sélection de `python`, moins d'une minute après le shell.

![P3-05](./artifacts/prd-1/demo/P3-05.png)

**6. Ouvre Explore sur VictoriaLogs — l'événement Kubescape détaillé s'affiche**

![P3-06](./artifacts/prd-1/demo/P3-06.png)

Explore s'ouvre directement sur VictoriaLogs, éditeur de requête chargé ; Grafana ne redémarre pas (compteur de redémarrages à 0 avant et après le parcours).

![P3-06b](./artifacts/prd-1/demo/P3-06b.png)

Saisi : `RuleID:R0001 AND RuntimeK8sDetails.namespace:="runtime-demo"`

![P3-06c](./artifacts/prd-1/demo/P3-06c.png)

Au premier clic sur « Run query », les résultats restent ceux de la requête `*` ; le second clic applique le filtre.

![P3-06d](./artifacts/prd-1/demo/P3-06d.png)

Six événements `Unexpected process launched` ; le plus récent (11:40:40, PID 7521) est le shell de la démo. L'utilisateur l'ouvre.

![P3-06e](./artifacts/prd-1/demo/P3-06e.png)

Le détail s'ouvre sous la ligne, hors de l'écran : l'utilisateur fait défiler.

![P3-06f](./artifacts/prd-1/demo/P3-06f.png)

Saisi dans la recherche du détail : `podName`

![P3-06g](./artifacts/prd-1/demo/P3-06g.png)

`RuntimeK8sDetails.podName` vaut `runtime-demo-86b997bf86-b4ss9`, le pod ciblé par la tâche.

![P3-06h](./artifacts/prd-1/demo/P3-06h.png)

**7. Ouvre Policy Reporter — les PolicyReports Kyverno sont listés, dont l'avertissement de base dépréciée et le registre hors liste en namespace plateforme**

![P3-07](./artifacts/prd-1/demo/P3-07.png)

`platform-registry-allow-list` : 8 résultats en échec ; l'utilisateur les ouvre.

![P3-07b](./artifacts/prd-1/demo/P3-07b.png)

Tous dans le namespace `observability` (Grafana, VictoriaLogs, VictoriaMetrics). L'utilisateur passe aux politiques d'image.

![P3-07c](./artifacts/prd-1/demo/P3-07c.png)

`workload-golden-base-deprecated` : 1 résultat, compté en « fail » et non en « warn ».

![P3-07d](./artifacts/prd-1/demo/P3-07d.png)

Écran final — le pod `demo-deprecated-base` du namespace `runtime-demo` :

![P3-fin](./artifacts/prd-1/demo/P3-fin.png)

## Écarts

- Les parcours web sont capturés à 1280×800 et non au format téléphone : à 390 px de large, Harbor superpose son menu latéral au contenu et rend les étapes illisibles.
- P3 étape 6 : le premier clic sur « Run query » n'a pas rafraîchi les résultats ; le second l'a fait (image P3-06d).
- P3 étape 6 : l'anneau de P3-06g est placé d'après la capture du panneau de détail, pas d'après la boîte de l'élément lue par script ; la saisie, elle, vise l'élément de l'arbre d'accessibilité.
