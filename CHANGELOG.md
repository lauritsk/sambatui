# Changelog
All notable changes to this project will be documented in this file. See [conventional commits](https://www.conventionalcommits.org/) for commit guidelines.

- - -
## [v0.7.1](https://github.com/lauritsk/sambatui/compare/0b1aaffd574435107c2ca720a936ce09a0f44bf1..v0.7.1) - 2026-05-16
#### Bug Fixes
- harden secret handling - ([1378dea](https://github.com/lauritsk/sambatui/commit/1378dea41e8f5eac6b6de06d5e98aed338d93c4d)) - Karl Hans Laurits
#### Documentation
- add project status - ([79117e0](https://github.com/lauritsk/sambatui/commit/79117e093612a86dcea0bb404bc68a7ee8dce54f)) - Karl Hans Laurits
#### Refactoring
- deduplicate selection handling - ([37e2511](https://github.com/lauritsk/sambatui/commit/37e25116a772883ab0a0fee6d815a6800de70dd2)) - Karl Hans Laurits
- simplify navigation and config helpers - ([4ac45dd](https://github.com/lauritsk/sambatui/commit/4ac45dd764fae7c0c5158f9014d70568bd8d7a34)) - Karl Hans Laurits
#### Miscellaneous Chores
- (**deps**) update pinned dependencies - ([7454805](https://github.com/lauritsk/sambatui/commit/7454805ee1eafda53e91488dbeeb1483a13b7e47)) - Karl Hans Laurits
- update local sambatui install - ([0b1aaff](https://github.com/lauritsk/sambatui/commit/0b1aaffd574435107c2ca720a936ce09a0f44bf1)) - Karl Hans Laurits

- - -

## [v0.7.0](https://github.com/lauritsk/sambatui/compare/242ce989a30e59298f021acfd8714dd8e43575c9..v0.7.0) - 2026-05-05
#### Features
- support selecting multiple smart findings - ([25be0be](https://github.com/lauritsk/sambatui/commit/25be0be789e0f681396dcc6c18b055d6721c83bb)) - Karl Hans Laurits
#### Bug Fixes
- (**config**) persist connection preference fields - ([a3cb4e1](https://github.com/lauritsk/sambatui/commit/a3cb4e1f46618f60ac331475a5670d2e64b52cb2)) - Karl Hans Laurits
- refresh DNS zones for smart PTR checks - ([985f61e](https://github.com/lauritsk/sambatui/commit/985f61e396ddf9a8e0974fd014940daea04fdf4d)) - Karl Hans Laurits
#### Tests
- (**dns**) isolate dashboard zone fixture - ([3d50d06](https://github.com/lauritsk/sambatui/commit/3d50d06cacd1108f098a2662bfc1471174f9759b)) - Karl Hans Laurits
#### Refactoring
- (**dns**) centralize record metadata and reverse zones - ([65bc5a8](https://github.com/lauritsk/sambatui/commit/65bc5a8ae1686933546484e8dd9625048961383d)) - Karl Hans Laurits
- (**ldap**) canonicalize DirectoryRow imports - ([d58d83d](https://github.com/lauritsk/sambatui/commit/d58d83d1f52bf395f90ac41f936ca9ed423b6e38)) - Karl Hans Laurits
- (**smart-views**) centralize finding metadata defaults - ([52c617d](https://github.com/lauritsk/sambatui/commit/52c617d051652f7860924647b8fc3c4e2c71cb46)) - Karl Hans Laurits
- (**smart-views**) inject reverse DNS resolver - ([eceba35](https://github.com/lauritsk/sambatui/commit/eceba3555f457c154d77734a17a54d78c45c7a93)) - Karl Hans Laurits
- (**smart-views**) centralize metadata defaults - ([1ff6f2b](https://github.com/lauritsk/sambatui/commit/1ff6f2b15dd61eb2b23841efb89fecaa5caa2bd1)) - Karl Hans Laurits
#### Miscellaneous Chores
- update local sambatui install - ([242ce98](https://github.com/lauritsk/sambatui/commit/242ce989a30e59298f021acfd8714dd8e43575c9)) - Karl Hans Laurits

- - -

## [v0.6.1](https://github.com/lauritsk/sambatui/compare/308cdb291de15d6ec7aff7e6b1899d4cee221efe..v0.6.1) - 2026-05-05
#### Bug Fixes
- (**test**) isolate LDAP selection notifications - ([308cdb2](https://github.com/lauritsk/sambatui/commit/308cdb291de15d6ec7aff7e6b1899d4cee221efe)) - Karl Hans Laurits

- - -

## [v0.6.0](https://github.com/lauritsk/sambatui/compare/89656baeea16ec5c3bcd8f28b38165fe2788360e..v0.6.0) - 2026-05-05
#### Features
- (**ldap**) support safe multi-select deletes - ([bf4a395](https://github.com/lauritsk/sambatui/commit/bf4a395c6c4696025343b1aa1c63ec8536d72d44)) - Karl Hans Laurits
#### Tests
- isolate config state - ([1c1f493](https://github.com/lauritsk/sambatui/commit/1c1f49380773914b03e8da036bca85dd833fc63e)) - Karl Hans Laurits
#### Miscellaneous Chores
- update local sambatui install - ([89656ba](https://github.com/lauritsk/sambatui/commit/89656baeea16ec5c3bcd8f28b38165fe2788360e)) - Karl Hans Laurits

- - -

## [v0.5.0](https://github.com/lauritsk/sambatui/compare/1a70d619e0aec799f7696e26f15b8595d44ea3e5..v0.5.0) - 2026-05-04
#### Features
- (**ui**) integrate findings into DNS and LDAP navigation - ([66c1e54](https://github.com/lauritsk/sambatui/commit/66c1e5405eb348fb66f5b649bdb24d9c8f719fda)) - Karl Hans Laurits
#### Bug Fixes
- (**ui**) restore smart view shortcut form - ([5778d71](https://github.com/lauritsk/sambatui/commit/5778d718d9debe3c6141d30e8b25d8ddee978613)) - Karl Hans Laurits
- (**ui**) streamline smart view sidebar - ([ef0b327](https://github.com/lauritsk/sambatui/commit/ef0b3277a5abeddeeb9a1cb61200ca25674fa927)) - Karl Hans Laurits
- limit LDAP dashboard searches - ([5681a23](https://github.com/lauritsk/sambatui/commit/5681a235ed1b514b5294f99ced42640862972f70)) - Karl Hans Laurits
- use initial domain for UPN suggestions - ([5ebe37d](https://github.com/lauritsk/sambatui/commit/5ebe37dbbc1f4ef4a76b4a9409f36badc456f399)) - Karl Hans Laurits
#### Documentation
- (**ui**) update findings terminology - ([0e99957](https://github.com/lauritsk/sambatui/commit/0e9995706225fcc35cc67a967bd934ce5c3016b0)) - Karl Hans Laurits
#### Refactoring
- simplify smart view threshold handling - ([bf9cca1](https://github.com/lauritsk/sambatui/commit/bf9cca1a39296dc680fce0511a32132a84ad5d88)) - Karl Hans Laurits
- simplify navigation table handling - ([0d72cf7](https://github.com/lauritsk/sambatui/commit/0d72cf7d0ff9f6191102da03bfe1d96c0f27478f)) - Karl Hans Laurits
#### Miscellaneous Chores
- update local sambatui install - ([1a70d61](https://github.com/lauritsk/sambatui/commit/1a70d619e0aec799f7696e26f15b8595d44ea3e5)) - Karl Hans Laurits

- - -

## [v0.4.0](https://github.com/lauritsk/sambatui/compare/d15dedba89b2548b2fb70ed1c1bf7b0889003d85..v0.4.0) - 2026-05-04
#### Features
- (**smart-views**) add sidebar run controls - ([80fe557](https://github.com/lauritsk/sambatui/commit/80fe557bb4ed2ca9d47a42132e2489197b92239c)) - Karl Hans Laurits
- (**smart-views**) add logical default sorting - ([248ab80](https://github.com/lauritsk/sambatui/commit/248ab808db79f5b0c892d7a343be725823d0c664)) - Karl Hans Laurits
- add guided LDAP smart fixes - ([5142175](https://github.com/lauritsk/sambatui/commit/51421752def278fe0c1c3d33a65cece353ec91fb)) - Karl Hans Laurits
#### Bug Fixes
- (**smart-views**) launch sidebar forms from worker - ([493054f](https://github.com/lauritsk/sambatui/commit/493054f1930c341f182cc7e3d448cd44d39952c4)) - Karl Hans Laurits
- (**smart-views**) preserve context when loading more - ([ce08d61](https://github.com/lauritsk/sambatui/commit/ce08d612018cf5a6d9a1eec9c21a56a18b5efa51)) - Karl Hans Laurits
#### Documentation
- require type-safe code and hypothesis tests - ([9a99c03](https://github.com/lauritsk/sambatui/commit/9a99c032a51c9cc933575eb7cfe674fb24dbfe9e)) - Karl Hans Laurits
#### Tests
- add hypothesis coverage for pure edge cases - ([ceac6f8](https://github.com/lauritsk/sambatui/commit/ceac6f813c079917f8ebe3b7783add9c361c0ef7)) - Karl Hans Laurits
- cover smart view sorting controls - ([395e0cf](https://github.com/lauritsk/sambatui/commit/395e0cffd8279dde305d2cbfee1dceb20143468f)) - Karl Hans Laurits
#### Refactoring
- simplify smart view helpers - ([3555db9](https://github.com/lauritsk/sambatui/commit/3555db9231c6efd05d0c0008480e8372a12eeb88)) - Karl Hans Laurits
- simplify record selection navigation - ([8df9dba](https://github.com/lauritsk/sambatui/commit/8df9dbaa176e5e422365a37688bcc52194dad6fe)) - Karl Hans Laurits
- simplify helper logic - ([5bf2cbc](https://github.com/lauritsk/sambatui/commit/5bf2cbcaff8ac866e9f23e2c7e80a90d7bfda1c0)) - Karl Hans Laurits
- make records view routing explicit - ([224145d](https://github.com/lauritsk/sambatui/commit/224145d02e8dda718b18e09bedb71323bca048a6)) - Karl Hans Laurits
- simplify smart view row loading - ([78ef763](https://github.com/lauritsk/sambatui/commit/78ef763681c983d4f76143f5de01fef97aff91bf)) - Karl Hans Laurits
#### Miscellaneous Chores
- update local sambatui install - ([d15dedb](https://github.com/lauritsk/sambatui/commit/d15dedba89b2548b2fb70ed1c1bf7b0889003d85)) - Karl Hans Laurits

- - -

## [v0.3.1](https://github.com/lauritsk/sambatui/compare/4e8345b9a4d3ab516685ffb6dfaa159e1e7930b5..v0.3.1) - 2026-05-04
#### Bug Fixes
- harden typing and private file writes - ([05270c6](https://github.com/lauritsk/sambatui/commit/05270c66a319c2c5246b9c554447db4d1fa5abf8)) - Karl Hans Laurits
#### Documentation
- align documentation with LDAP management - ([7f4b3c3](https://github.com/lauritsk/sambatui/commit/7f4b3c3f7087cdd11bc445401043d7a8f30732d2)) - Karl Hans Laurits
#### Tests
- avoid url substring assertion - ([ed091ab](https://github.com/lauritsk/sambatui/commit/ed091abdc8cd9462dae245655942792ddb0a9a9e)) - Karl Hans Laurits
- expand hypothesis coverage - ([959bb15](https://github.com/lauritsk/sambatui/commit/959bb150be23b2f8a37e47bdfa408483074aeb23)) - Karl Hans Laurits
- cover controllers completely - ([26fbd43](https://github.com/lauritsk/sambatui/commit/26fbd43e8a2b568e417fc5883910df8e04e5971d)) - Karl Hans Laurits
- mirror source tree structure - ([f3c5251](https://github.com/lauritsk/sambatui/commit/f3c52518a33c682f0b0770b551dfe2800576a2e9)) - Karl Hans Laurits
- isolate ldap add test from environment - ([c3c3bc1](https://github.com/lauritsk/sambatui/commit/c3c3bc15a22683b84d5d9075df81b4df95d43902)) - Karl Hans Laurits
- add property coverage for edge cases - ([8350fb3](https://github.com/lauritsk/sambatui/commit/8350fb32ab23d6060666cbc552e23a827afcd294)) - Karl Hans Laurits
- split coverage edge tests - ([389e4b6](https://github.com/lauritsk/sambatui/commit/389e4b6e9e6a8255d9c1aa6144c066b6d0ec19a5)) - Karl Hans Laurits
#### Refactoring
- (**core**) share common controller helpers - ([dd5e3ee](https://github.com/lauritsk/sambatui/commit/dd5e3eed84e616bcf08603e3d5b771d3b8caa1ce)) - Karl Hans Laurits
- simplify project code - ([196ab72](https://github.com/lauritsk/sambatui/commit/196ab72c4aeab8d96ea6e1ac95802f6a2cf330bf)) - Karl Hans Laurits
- improve test and ldap maintainability - ([7fb1113](https://github.com/lauritsk/sambatui/commit/7fb1113bd38cc75a0812d8e0eec786bd0ece6306)) - Karl Hans Laurits
- remove legacy compatibility shims - ([1e2876b](https://github.com/lauritsk/sambatui/commit/1e2876b9053797ce23b220a3b1c1d8fedf6678cf)) - Karl Hans Laurits
- split app controllers and views - ([1d46aea](https://github.com/lauritsk/sambatui/commit/1d46aea12b69c513f2a489205f96463133455f50)) - Karl Hans Laurits
- simplify validation helpers - ([4e8345b](https://github.com/lauritsk/sambatui/commit/4e8345b9a4d3ab516685ffb6dfaa159e1e7930b5)) - Karl Hans Laurits

- - -

## [v0.3.0](https://github.com/lauritsk/sambatui/compare/5a7e1b967c4211903d6070423bdf88e0f7d27555..v0.3.0) - 2026-05-04
#### Features
- add LDAP entry management - ([1e8a4dc](https://github.com/lauritsk/sambatui/commit/1e8a4dc641369817960b1aa93842fd08da7aa435)) - Karl Hans Laurits
#### Miscellaneous Chores
- update mise tools - ([9897ee2](https://github.com/lauritsk/sambatui/commit/9897ee2383829c9b461aa03a49f1f40fd38a922d)) - Karl Hans Laurits
- update local sambatui version - ([5a7e1b9](https://github.com/lauritsk/sambatui/commit/5a7e1b967c4211903d6070423bdf88e0f7d27555)) - Karl Hans Laurits

- - -

## [v0.2.0](https://github.com/lauritsk/sambatui/compare/40e2d75361a18e1ebd76df0864e6deafc9d6ae06..v0.2.0) - 2026-05-01
#### Features
- edit allowlisted LDAP attributes - ([64ae8d2](https://github.com/lauritsk/sambatui/commit/64ae8d2f52ea6c7bc89d0114d4ed0c9c4fa6541d)) - Karl Hans Laurits
#### Miscellaneous Chores
- add prod version of sambatui tool - ([40e2d75](https://github.com/lauritsk/sambatui/commit/40e2d75361a18e1ebd76df0864e6deafc9d6ae06)) - Karl Hans Laurits

- - -

## [v0.1.1](https://github.com/lauritsk/sambatui/compare/e563a379796a4e0fe0098917be267992ee58d446..v0.1.1) - 2026-05-01
#### Bug Fixes
- (**release**) restore multi-arch image build - ([e563a37](https://github.com/lauritsk/sambatui/commit/e563a379796a4e0fe0098917be267992ee58d446)) - Karl Hans Laurits

- - -

## [v0.1.0](https://github.com/lauritsk/sambatui/compare/e35fba27da80ef41bf0b921a90de28e4c697d6f0..v0.1.0) - 2026-05-01
#### Features
- (**auth**) auto-detect kerberos setup - ([721f5c4](https://github.com/lauritsk/sambatui/commit/721f5c4b76a6bd292804c0142ecbb6e17afa8671)) - Karl Hans Laurits
- (**config**) persist user preferences - ([d6a8a2e](https://github.com/lauritsk/sambatui/commit/d6a8a2e29dbfdababca1aeb797948d26043782db)) - Karl Hans Laurits
- (**discovery**) harden client and discover controllers - ([95e2e55](https://github.com/lauritsk/sambatui/commit/95e2e55239d2e405cd5a2a253b832f1d55fb0232)) - Karl Hans Laurits
- (**dns**) add guided record creation flow - ([175b434](https://github.com/lauritsk/sambatui/commit/175b434542bdcdcae2d555f4d80791b82212acd3)) - Karl Hans Laurits
- (**dns**) restore active zone records - ([57d2e5e](https://github.com/lauritsk/sambatui/commit/57d2e5e78954206ff8fdcadf53a81a2f5dbdc5de)) - Karl Hans Laurits
- (**ldap**) add legacy compatibility mode - ([516e0ec](https://github.com/lauritsk/sambatui/commit/516e0ec1766bee166d2a5c2b6ab6230ac629ae89)) - Karl Hans Laurits
- (**ldap**) support kerberos directory bind - ([9bb2beb](https://github.com/lauritsk/sambatui/commit/9bb2bebd91abe6a7c50ff1b5967a6994f37c2438)) - Karl Hans Laurits
- (**ldap**) add read-only directory search - ([bae88b1](https://github.com/lauritsk/sambatui/commit/bae88b1a0703770e5e1b0a4f3fc4e64970b25fd7)) - Karl Hans Laurits
- (**search**) add inline live filtering - ([f38a358](https://github.com/lauritsk/sambatui/commit/f38a358feea3bc8d147013b8bc0dde9e198b08ee)) - Karl Hans Laurits
- (**setup**) suggest upn domain suffix - ([c9057a5](https://github.com/lauritsk/sambatui/commit/c9057a5545c314b6ab51e98ed6a5666dfb7ee952)) - Karl Hans Laurits
- (**smart**) add full health dashboard - ([793b2d6](https://github.com/lauritsk/sambatui/commit/793b2d6faaadfdecc5dfee76d8d019ce10f0d261)) - Karl Hans Laurits
- (**smart**) add guided PTR remediation - ([6dc9693](https://github.com/lauritsk/sambatui/commit/6dc9693b326e06480730b38a778a38a2efa593b8)) - Karl Hans Laurits
- (**smart-views**) add DNS and LDAP hygiene views - ([c521b7d](https://github.com/lauritsk/sambatui/commit/c521b7d831a0149332995b7f9157f07f31939777)) - Karl Hans Laurits
- (**ui**) expand LDAP sidebar containers - ([72dc5f8](https://github.com/lauritsk/sambatui/commit/72dc5f8042b314c4d58b458e9588a415d7aaaf68)) - Karl Hans Laurits
- (**ui**) make LDAP sidebar root load entries - ([98860ab](https://github.com/lauritsk/sambatui/commit/98860ab0449390a140449eb12416bd84c3dbf933)) - Karl Hans Laurits
- (**ui**) preload LDAP sidebar views - ([3ea0a4d](https://github.com/lauritsk/sambatui/commit/3ea0a4d52fd3c8e1d79ce13ef269118dd2881382)) - Karl Hans Laurits
- (**ui**) show LDAP structure in sidebar - ([5e108b7](https://github.com/lauritsk/sambatui/commit/5e108b790287f4e811a49eba56df89c4800223c2)) - Karl Hans Laurits
- (**ux**) add first-run setup wizard - ([d01997f](https://github.com/lauritsk/sambatui/commit/d01997fb2d53c072a7154e1ccc1a8786dfd605d3)) - Karl Hans Laurits
- (**ux**) add command palette - ([25976e6](https://github.com/lauritsk/sambatui/commit/25976e6cfe8e5a8fbd4d02d86efc888401dd3280)) - Karl Hans Laurits
- (**ux**) add sidebar action buttons - ([12a33e2](https://github.com/lauritsk/sambatui/commit/12a33e2fb4229e11f71c5304c31eaa88d67c7eca)) - Karl Hans Laurits
- (**ux**) add selected-row details pane - ([f31d21d](https://github.com/lauritsk/sambatui/commit/f31d21de00d4fb4539846503904bfa695e2c47fc)) - Karl Hans Laurits
- (**ux**) improve empty and error states - ([b9b9b36](https://github.com/lauritsk/sambatui/commit/b9b9b36f910ecd59e7956ed594009512724a4e97)) - Karl Hans Laurits
- add LDAP pagination load more - ([2f6a803](https://github.com/lauritsk/sambatui/commit/2f6a8033dd048660395394d156debce696af6701)) - Karl Hans Laurits
- add smart view picker - ([db5e1b7](https://github.com/lauritsk/sambatui/commit/db5e1b7dbf33524161926d2bd3b23a96c0ba7abc)) - Karl Hans Laurits
- autofill connection form defaults - ([0861b6e](https://github.com/lauritsk/sambatui/commit/0861b6e5ddedeb71a3a15d3393efafefaa83864a)) - Karl Hans Laurits
- simplify DNS and LDAP sidebar - ([56dc247](https://github.com/lauritsk/sambatui/commit/56dc247d53497ce31e018a4d49004103cb02a462)) - Karl Hans Laurits
- simplify TUI connection layout - ([5667a31](https://github.com/lauritsk/sambatui/commit/5667a31e3ab15590f679fb67ca9fbd165175e1c4)) - Karl Hans Laurits
#### Bug Fixes
- (**config**) validate saved preferences - ([8649f26](https://github.com/lauritsk/sambatui/commit/8649f260601052c4d9baf471a3e673eb03bdaf9e)) - Karl Hans Laurits
- (**keyboard**) complete shortcut navigation - ([28314c2](https://github.com/lauritsk/sambatui/commit/28314c2de3e162485df951759f8a04f195c91760)) - Karl Hans Laurits
- (**ldap**) handle server-terminated binds - ([4adf57b](https://github.com/lauritsk/sambatui/commit/4adf57bcc57a644308fd530cf582e2e52b175360)) - Karl Hans Laurits
- (**search**) query source records for inline search - ([fdbe9cc](https://github.com/lauritsk/sambatui/commit/fdbe9cc662402cf8e5ba6a8b1077d9589ba8261f)) - Karl Hans Laurits
- (**setup**) accept upn suffix on blur - ([9eef466](https://github.com/lauritsk/sambatui/commit/9eef466247452880bb76b16575286f66db5fc7e4)) - Karl Hans Laurits
- (**setup**) separate AD domain from active DNS zone - ([cb89208](https://github.com/lauritsk/sambatui/commit/cb89208b4aa0bccb686882ab7e721974e6f55add)) - Karl Hans Laurits
- (**ui**) suppress LDAP container expansion errors - ([1eabaa7](https://github.com/lauritsk/sambatui/commit/1eabaa7d627f38e06c5962c63452bb21f8a474f1)) - Karl Hans Laurits
- (**ui**) keep LDAP sidebar subtree selection - ([90f9500](https://github.com/lauritsk/sambatui/commit/90f950060c2d2466a5d510af6b955242b5768a0f)) - Karl Hans Laurits
- (**ui**) render command errors as plain text - ([eb8f32f](https://github.com/lauritsk/sambatui/commit/eb8f32fbf44e0df7c0f2fcfb4acbd0325d2e80fa)) - Karl Hans Laurits
- (**ui**) keep modal tab focus in foreground - ([7b4e5b7](https://github.com/lauritsk/sambatui/commit/7b4e5b7c11ad980b9161ac7e8ee3e5a6158a1dbc)) - Karl Hans Laurits
- (**ui**) stabilize LDAP sidebar selection - ([5355741](https://github.com/lauritsk/sambatui/commit/535574125abd99570c0e2193eb91df0132a09a92)) - Karl Hans Laurits
- (**ui**) show only real LDAP tree rows - ([e28aad1](https://github.com/lauritsk/sambatui/commit/e28aad14e6340075eb4e2fad9a52cdd75bcd213b)) - Karl Hans Laurits
- ensure rumdl ignores changelog formatting - ([5724094](https://github.com/lauritsk/sambatui/commit/57240940e2cc786b602da898d96ca2c4e544ab50)) - Karl Hans Laurits
- sort LDAP rows by header - ([8e2aae8](https://github.com/lauritsk/sambatui/commit/8e2aae81e963bd5c62451a8e415c1c685e902145)) - Karl Hans Laurits
- preserve LDAP sidebar selection - ([58ef469](https://github.com/lauritsk/sambatui/commit/58ef4694c67c83629ceaab3ddcf1c0070208f9ee)) - Karl Hans Laurits
- prompt for PTR records when adding A records - ([bee1efb](https://github.com/lauritsk/sambatui/commit/bee1efba38b289513ce9f196bfb92f2864e33f56)) - Karl Hans Laurits
- run smart view shortcuts in worker - ([2b2287f](https://github.com/lauritsk/sambatui/commit/2b2287f998ea13873f5b1988297b16064e2274e8)) - Karl Hans Laurits
- add side tab navigation shortcuts - ([2993e15](https://github.com/lauritsk/sambatui/commit/2993e15f6f80573d8bf7203c4cf5a71294b53029)) - Karl Hans Laurits
#### Documentation
- (**ldap**) recommend UPN bind username - ([4835719](https://github.com/lauritsk/sambatui/commit/4835719bae73afc6f4a4293d41de075b1b9ad7f4)) - Karl Hans Laurits
- update security audit - ([d7c6b9b](https://github.com/lauritsk/sambatui/commit/d7c6b9b4d5d1454e4992e2985c3fdd05fbff1285)) - Karl Hans Laurits
- refresh README - ([60abf57](https://github.com/lauritsk/sambatui/commit/60abf57edc7e5dd444b639c3aa5f08d55c8df7c9)) - Karl Hans Laurits
- align user and contributor docs - ([82afa20](https://github.com/lauritsk/sambatui/commit/82afa20ddf5b5eaf309ffd94102501bffaeb762c)) - Karl Hans Laurits
- normalize sambatui task casing - ([fe8a902](https://github.com/lauritsk/sambatui/commit/fe8a90214f039ce2f453a32f1df6dc1ff0f83b94)) - Karl Hans Laurits
- document Samba system dependencies - ([b204537](https://github.com/lauritsk/sambatui/commit/b20453756968fde7dae986bf3ee783bfa4513e94)) - Karl Hans Laurits
- normalize project name casing - ([f1265e9](https://github.com/lauritsk/sambatui/commit/f1265e9ab58f8ce8fb0d3a095c16ac3520fcb414)) - Karl Hans Laurits
- add security audit results - ([b108f44](https://github.com/lauritsk/sambatui/commit/b108f447be6ddeed7d94792c3bc717757665622b)) - Karl Hans Laurits
#### Tests
- (**coverage**) require 95 percent coverage - ([d0ef313](https://github.com/lauritsk/sambatui/commit/d0ef31379d573e6c46c7adde97dac7953465b3e6)) - Karl Hans Laurits
- (**ui**) make LDAP empty state deterministic - ([3697b7c](https://github.com/lauritsk/sambatui/commit/3697b7cb38c413a1c3b69d19ebfbd9824440b945)) - Karl Hans Laurits
#### Refactoring
- (**app**) reduce flow complexity - ([56ec20b](https://github.com/lauritsk/sambatui/commit/56ec20b6f23dd348fcf8d972dd989377b138225d)) - Karl Hans Laurits
- (**app**) extract LDAP sidebar helpers - ([33dc6d1](https://github.com/lauritsk/sambatui/commit/33dc6d1e0c3604fbd45f9caeefab0fe5e6492b51)) - Karl Hans Laurits
- (**app**) centralize action dispatch - ([20dccd5](https://github.com/lauritsk/sambatui/commit/20dccd518f97a40e23c3358f01dff4a7eaef987c)) - Karl Hans Laurits
- (**app**) simplify smart-view orchestration - ([caefc98](https://github.com/lauritsk/sambatui/commit/caefc9829d49943d995297772215e9e62e1b2af1)) - Karl Hans Laurits
- (**app**) split UI helpers and settings - ([537c659](https://github.com/lauritsk/sambatui/commit/537c6594a6c829fc3a7ba1c14a7c1f282a2fde79)) - Karl Hans Laurits
- (**app**) simplify repeated view logic - ([2185162](https://github.com/lauritsk/sambatui/commit/21851629e4af338098019f9edd178e93546a89fa)) - Karl Hans Laurits
- (**app**) split DNS helpers from TUI - ([d251ef2](https://github.com/lauritsk/sambatui/commit/d251ef242b96d4d38b372dcdf9f9a0de4da1c3d3)) - Karl Hans Laurits
- (**core**) split app responsibilities - ([7ad85b8](https://github.com/lauritsk/sambatui/commit/7ad85b8d30453d69b2786444020fc04352ee956f)) - Karl Hans Laurits
- (**dns**) use dnspython helpers - ([9eacd1d](https://github.com/lauritsk/sambatui/commit/9eacd1d4cedda46383a1edf0e8718b5b5a4c81ca)) - Karl Hans Laurits
- (**smart-views**) extract finding builders - ([f07c2f7](https://github.com/lauritsk/sambatui/commit/f07c2f749fa8f7648a1ce98780cb7da72fda3dd4)) - Karl Hans Laurits
- simplify app helpers - ([c807598](https://github.com/lauritsk/sambatui/commit/c8075982e062fdef90c676ffef082eba34bc5aae)) - Karl Hans Laurits
- simplify project code - ([27d23c1](https://github.com/lauritsk/sambatui/commit/27d23c11f8d7212a11401fcb46f248b4a2d12d80)) - Karl Hans Laurits
- remove stale compatibility code - ([4fe7a2e](https://github.com/lauritsk/sambatui/commit/4fe7a2e242a896a3d9bf64d601ee3017121070ed)) - Karl Hans Laurits
- simplify guided record helpers - ([99069e4](https://github.com/lauritsk/sambatui/commit/99069e4f10178167cceef2ff853f712ce7d8ffc3)) - Karl Hans Laurits
- simplify core helpers - ([42e90e4](https://github.com/lauritsk/sambatui/commit/42e90e4371cedb742e4928745a896d9711643d18)) - Karl Hans Laurits
- split app composition helpers - ([ac5b9a0](https://github.com/lauritsk/sambatui/commit/ac5b9a015f1735ab0a5d4d76e85f22956fcba522)) - Karl Hans Laurits
- simplify DNS and selection helpers - ([f90c887](https://github.com/lauritsk/sambatui/commit/f90c8874c031a6d641b457ee16a33c7e17e121dd)) - Karl Hans Laurits
- simplify key and validation helpers - ([81c8616](https://github.com/lauritsk/sambatui/commit/81c8616c6feaa72b915773b66ffd0e9a84e53f0c)) - Karl Hans Laurits
- extract smart view catalog - ([5616350](https://github.com/lauritsk/sambatui/commit/56163502db671d8b86b4fde15e7d34f5251b3785)) - Karl Hans Laurits
- simplify TUI form and update flows - ([19e7393](https://github.com/lauritsk/sambatui/commit/19e7393755c40dd6c9201971bc64971f71d4f29c)) - Karl Hans Laurits
- simplify app and LDAP helpers - ([91e6a77](https://github.com/lauritsk/sambatui/commit/91e6a773bb7661df3cf77d03ef2b037a0d656606)) - Karl Hans Laurits
- extract remediation helpers - ([05eb89a](https://github.com/lauritsk/sambatui/commit/05eb89a681fa9d701af2586797cb06b0ef7ac4f5)) - Karl Hans Laurits
- consolidate table rendering helpers - ([922448e](https://github.com/lauritsk/sambatui/commit/922448ef220254af325fb98f822c20f572340a02)) - Karl Hans Laurits
#### Miscellaneous Chores
- remove changelog - ([8401090](https://github.com/lauritsk/sambatui/commit/840109007c304af9e3c6f030666f34345d2ae63f)) - Karl Hans Laurits
- update mise tools - ([067749f](https://github.com/lauritsk/sambatui/commit/067749ff2d9fbcc434a4bb71d66b923c710d64ca)) - Karl Hans Laurits
- update mise lockfile - ([dda4e47](https://github.com/lauritsk/sambatui/commit/dda4e47f41a04625e336bebb03cc2cb6b93dcd2c)) - Karl Hans Laurits
- adopt mature project tooling - ([90d2882](https://github.com/lauritsk/sambatui/commit/90d2882285de98924c34ce57b649ebeebac752a8)) - Karl Hans Laurits
- switch to latest python and regenerate venv - ([83a4949](https://github.com/lauritsk/sambatui/commit/83a4949b0127612d80aa9a2c7fe8591ce2c76f2b)) - Karl Hans Laurits
- initial commit - ([e35fba2](https://github.com/lauritsk/sambatui/commit/e35fba27da80ef41bf0b921a90de28e4c697d6f0)) - Karl Hans Laurits

- - -

Changelog generated by [cocogitto](https://github.com/cocogitto/cocogitto).