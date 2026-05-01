# Changelog
All notable changes to this project will be documented in this file. See [conventional commits](https://www.conventionalcommits.org/) for commit guidelines.

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