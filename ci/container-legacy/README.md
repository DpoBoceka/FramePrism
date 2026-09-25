# container-legacy — the legacy bsdtar container fixture

`legacy-clip.tar.zst` — the legacy-compatibility pin for the in-process
container reader (the bake container pipeline left the
system-tool subprocesses). ONE data file, built (macos aarch64) with
the exact legacy invocation on the system tools of the day — bsdtar
3.5.3 - libarchive 3.5.3 + zstd v1.5.7 (upstream author: Yann Collet):

    tar --no-mac-metadata -cf - -C <in> <files...> | zstd -19 -q -T0 -o <out>

The member listing is 3 synthetic .DNGs (bare member names, no
directories — the bake manifest's relpath namespace). Asset = DATA, not
a regeneration fixture: its sha256 is pinned INSIDE the T2 test
(`legacy_bsdtar_fixture_read`), which re-hashes the committed file on
every run before reading it. Purpose: the in-process audit reader must
accept the legacy containers — the fixture is the clone-ready proof
(the fresh-shell gate's tree is self-contained).
