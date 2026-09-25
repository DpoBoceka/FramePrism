# NOTICE — third-party components and licenses

FramePrism (this repository) is licensed under the MIT License (see
`LICENSE`). This repository redistributes the third-party artifacts
below and incorporates the third-party code below. Applicable license
texts are reproduced here or incorporated by reference where noted; the
per-component narrative lives in `docs/third-party.md`.

## Committed artifacts

### libjpeg-turbo (the committed `.jpeg-prefix`)

`deps/.jpeg-prefix/{lib,include}` — the pinned patched libjpeg-turbo
build (the version `3.2.1` per the committed pkgconfig files; the
pinned source commit `d9b5af99e53591c0b51ba82bea3a0874b78c4c20` + the
per-component lossless DHT patch). The static libraries
`libturbojpeg.a` / `libjpeg.a` + the public headers.

libjpeg-turbo is covered by two compatible BSD-style licenses: the
IJG (Independent JPEG Group) License (the libjpeg API library and the
inherited code) and the Modified (3-clause) BSD License (the
TurboJPEG API). Its component licenses (zlib for the SIMD sources;
libpng-2.0 / BSD-2-Clause for the libspng used by cjpeg/djpeg) are
subsumed by those two in this context. The full roll-up + compliance
terms: the pinned commit's `LICENSE.md` (
https://github.com/libjpeg-turbo/libjpeg-turbo/blob/d9b5af99e53591c0b51ba82bea3a0874b78c4c20/LICENSE.md ).

The IJG License's distribution conditions are met by this file: the
LEGAL ISSUES license terms (the "In legalese" body) are reproduced
verbatim below, and this product documentation states that the
software is based in part on the work of the Independent JPEG Group.

FramePrism's lossless JPEG path is based in part on the work of the
Independent JPEG Group.

#### The IJG License — the LEGAL ISSUES license terms (verbatim,
the pinned commit's `README.ijg`)

In legalese:

The authors make NO WARRANTY or representation, either express or
implied, with respect to this software, its quality, accuracy,
merchantability, or fitness for a particular purpose.  This software
is provided "AS IS", and you, its user, assume the entire risk as to
its quality and accuracy.

This software is copyright (C) 1991-2020, Thomas G. Lane, Guido
Vollbeding.  All Rights Reserved except as specified below.

Permission is hereby granted to use, copy, modify, and distribute
this software (or portions thereof) for any purpose, without fee,
subject to these conditions:
(1) If any part of the source code for this software is
    distributed, then this README file must be included, with this
    copyright and no-warranty notice unaltered; and any additions,
    deletions, or changes to the original files must be clearly
    indicated in accompanying documentation.
(2) If only executable code is distributed, then the accompanying
    documentation must state that "this software is based in part on
    the work of the Independent JPEG Group".
(3) Permission for use of this software is granted only if the user
    accepts full responsibility for any undesirable consequences; the
    authors accept NO LIABILITY for damages of any kind.

These conditions apply to any software derived from or based on the
IJG code, not just to the unmodified library.  If you use our work,
you ought to acknowledge us.

Permission is NOT granted for the use of any IJG author's name or
company name in advertising or publicity relating to this software or
products derived from it.  This software may be referred to only as
"the Independent JPEG Group's software".

The LEGAL ISSUES section's remaining paragraphs (the plain-English
preamble and the closing commercial-use sentence) are unchanged in
the pinned commit's `README.ijg` (
https://github.com/libjpeg-turbo/libjpeg-turbo/blob/d9b5af99e53591c0b51ba82bea3a0874b78c4c20/README.ijg ),
which is the authoritative record of the full section.

#### The Modified (3-clause) BSD License (verbatim, the pinned
commit's `LICENSE.md`)

Copyright (C) 2009-2026 D. R. Commander
Copyright (C) 2018-2023 Randy <randy408@protonmail.com>

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:

- Redistributions of source code must retain the above copyright
  notice, this list of conditions and the following disclaimer.
- Redistributions in binary form must reproduce the above copyright
  notice, this list of conditions and the following disclaimer in the
  documentation and/or other materials provided with the
  distribution.
- Neither the name of the libjpeg-turbo Project nor the names of its
  contributors may be used to endorse or promote products derived from
  this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS", AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT
HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
DAMAGE.

### libjxl (the pinned cjxl/djxl binaries + the runtime dylibs)

`deps/pinned-binaries/{cjxl,djxl}` (the pinned v0.12.0 local NEON
build) + `deps/.jxl-libs/*.dylib` (the libjxl v0.12.0 runtime).
libjxl is BSD-3-Clause. The build bundles three components statically:
brotli (MIT), highway (Apache-2.0), and skcms (BSD-3-Clause) — verified
from the committed dylibs (the local-symbol census). The BSD-3-Clause and MIT
texts follow (libjxl, then the bundled components).

#### libjxl — BSD 3-Clause (verbatim, the v0.12.0 `LICENSE`)

Copyright (c) the JPEG XL Project Authors.
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its
   contributors may be used to endorse or promote products derived from
   this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#### brotli (bundled in the libjxl dylibs) — MIT (verbatim, the
upstream `LICENSE`)

Copyright (c) 2009, 2010, 2013-2016 by the Brotli Authors.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.

#### skcms (bundled in the libjxl dylibs) — BSD 3-Clause (verbatim,
the upstream `LICENSE`)

Copyright (c) 2018 Google Inc. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

   * Redistributions of source code must retain the above copyright
     notice, this list of conditions and the following disclaimer.
   * Redistributions in binary form must reproduce the above
     copyright notice, this list of conditions and the following
     disclaimer in the documentation and/or other materials provided
     with the distribution.
   * Neither the name of Google Inc. nor the names of its
     contributors may be used to endorse or promote products derived
     from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#### highway (bundled in the libjxl dylibs) — Apache 2.0 (verbatim, the
upstream `LICENSE` at the libjxl v0.12.0 pinned submodule SHA)

                                 Apache License
                           Version 2.0, January 2004
                        http://www.apache.org/licenses/

   TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION

   1. Definitions.

      "License" shall mean the terms and conditions for use, reproduction,
      and distribution as defined by Sections 1 through 9 of this document.

      "Licensor" shall mean the copyright owner or entity authorized by
      the copyright owner that is granting the License.

      "Legal Entity" shall mean the union of the acting entity and all
      other entities that control, are controlled by, or are under common
      control with that entity. For the purposes of this definition,
      "control" means (i) the power, direct or indirect, to cause the
      direction or management of such entity, whether by contract or
      otherwise, or (ii) ownership of fifty percent (50%) or more of the
      outstanding shares, or (iii) beneficial ownership of such entity.

      "You" (or "Your") shall mean an individual or Legal Entity
      exercising permissions granted by this License.

      "Source" form shall mean the preferred form for making modifications,
      including but not limited to software source code, documentation
      source, and configuration files.

      "Object" form shall mean any form resulting from mechanical
      transformation or translation of a Source form, including but
      not limited to compiled object code, generated documentation,
      and conversions to other media types.

      "Work" shall mean the work of authorship, whether in Source or
      Object form, made available under the License, as indicated by a
      copyright notice that is included in or attached to the work
      (an example is provided in the Appendix below).

      "Derivative Works" shall mean any work, whether in Source or Object
      form, that is based on (or derived from) the Work and for which the
      editorial revisions, annotations, elaborations, or other modifications
      represent, as a whole, an original work of authorship. For the purposes
      of this License, Derivative Works shall not include works that remain
      separable from, or merely link (or bind by name) to the interfaces of,
      the Work and Derivative Works thereof.

      "Contribution" shall mean any work of authorship, including
      the original version of the Work and any modifications or additions
      to that Work or Derivative Works thereof, that is intentionally
      submitted to Licensor for inclusion in the Work by the copyright owner
      or by an individual or Legal Entity authorized to submit on behalf of
      the copyright owner. For the purposes of this definition, "submitted"
      means any form of electronic, verbal, or written communication sent
      to the Licensor or its representatives, including but not limited to
      communication on electronic mailing lists, source code control systems,
      and issue tracking systems that are managed by, or on behalf of, the
      Licensor for the purpose of discussing and improving the Work, but
      excluding communication that is conspicuously marked or otherwise
      designated in writing by the copyright owner as "Not a Contribution."

      "Contributor" shall mean Licensor and any individual or Legal Entity
      on behalf of whom a Contribution has been received by Licensor and
      subsequently incorporated within the Work.

   2. Grant of Copyright License. Subject to the terms and conditions of
      this License, each Contributor hereby grants to You a perpetual,
      worldwide, non-exclusive, no-charge, royalty-free, irrevocable
      copyright license to reproduce, prepare Derivative Works of,
      publicly display, publicly perform, sublicense, and distribute the
      Work and such Derivative Works in Source or Object form.

   3. Grant of Patent License. Subject to the terms and conditions of
      this License, each Contributor hereby grants to You a perpetual,
      worldwide, non-exclusive, no-charge, royalty-free, irrevocable
      (except as stated in this section) patent license to make, have made,
      use, offer to sell, sell, import, and otherwise transfer the Work,
      where such license applies only to those patent claims licensable
      by such Contributor that are necessarily infringed by their
      Contribution(s) alone or by combination of their Contribution(s)
      with the Work to which such Contribution(s) was submitted. If You
      institute patent litigation against any entity (including a
      cross-claim or counterclaim in a lawsuit) alleging that the Work
      or a Contribution incorporated within the Work constitutes direct
      or contributory patent infringement, then any patent licenses
      granted to You under this License for that Work shall terminate
      as of the date such litigation is filed.

   4. Redistribution. You may reproduce and distribute copies of the
      Work or Derivative Works thereof in any medium, with or without
      modifications, and in Source or Object form, provided that You
      meet the following conditions:

      (a) You must give any other recipients of the Work or
          Derivative Works a copy of this License; and

      (b) You must cause any modified files to carry prominent notices
          stating that You changed the files; and

      (c) You must retain, in the Source form of any Derivative Works
          that You distribute, all copyright, patent, trademark, and
          attribution notices from the Source form of the Work,
          excluding those notices that do not pertain to any part of
          the Derivative Works; and

      (d) If the Work includes a "NOTICE" text file as part of its
          distribution, then any Derivative Works that You distribute must
          include a readable copy of the attribution notices contained
          within such NOTICE file, excluding those notices that do not
          pertain to any part of the Derivative Works, in at least one
          of the following places: within a NOTICE text file distributed
          as part of the Derivative Works; within the Source form or
          documentation, if provided along with the Derivative Works; or,
          within a display generated by the Derivative Works, if and
          wherever such third-party notices normally appear. The contents
          of the NOTICE file are for informational purposes only and
          do not modify the License. You may add Your own attribution
          notices within Derivative Works that You distribute, alongside
          or as an addendum to the NOTICE text from the Work, provided
          that such additional attribution notices cannot be construed
          as modifying the License.

      You may add Your own copyright statement to Your modifications and
      may provide additional or different license terms and conditions
      for use, reproduction, or distribution of Your modifications, or
      for any such Derivative Works as a whole, provided Your use,
      reproduction, and distribution of the Work otherwise complies with
      the conditions stated in this License.

   5. Submission of Contributions. Unless You explicitly state otherwise,
      any Contribution intentionally submitted for inclusion in the Work
      by You to the Licensor shall be under the terms and conditions of
      this License, without any additional terms or conditions.
      Notwithstanding the above, nothing herein shall supersede or modify
      the terms of any separate license agreement you may have executed
      with Licensor regarding such Contributions.

   6. Trademarks. This License does not grant permission to use the trade
      names, trademarks, service marks, or product names of the Licensor,
      except as required for reasonable and customary use in describing the
      origin of the Work and reproducing the content of the NOTICE file.

   7. Disclaimer of Warranty. Unless required by applicable law or
      agreed to in writing, Licensor provides the Work (and each
      Contributor provides its Contributions) on an "AS IS" BASIS,
      WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
      implied, including, without limitation, any warranties or conditions
      of TITLE, NON-INFRINGEMENT, MERCHANTABILITY, or FITNESS FOR A
      PARTICULAR PURPOSE. You are solely responsible for determining the
      appropriateness of using or redistributing the Work and assume any
      risks associated with Your exercise of permissions under this License.

   8. Limitation of Liability. In no event and under no legal theory,
      whether in tort (including negligence), contract, or otherwise,
      unless required by applicable law (such as deliberate and grossly
      negligent acts) or agreed to in writing, shall any Contributor be
      liable to You for damages, including any direct, indirect, special,
      incidental, or consequential damages of any character arising as a
      result of this License or out of the use or inability to use the
      Work (including but not limited to damages for loss of goodwill,
      work stoppage, computer failure or malfunction, or any and all
      other commercial damages or losses), even if such Contributor
      has been advised of the possibility of such damages.

   9. Accepting Warranty or Additional Liability. While redistributing
      the Work or Derivative Works thereof, You may choose to offer,
      and charge a fee for, acceptance of support, warranty, indemnity,
      or other liability obligations and/or rights consistent with this
      License. However, in accepting such obligations, You may act only
      on Your own behalf and on Your sole responsibility, not on behalf
      of any other Contributor, and only if You agree to indemnify,
      defend, and hold each Contributor harmless for any liability
      incurred by, or claims asserted against, such Contributor by reason
      of your accepting any such warranty or additional liability.

   END OF TERMS AND CONDITIONS

   APPENDIX: How to apply the Apache License to your work.

      To apply the Apache License to your work, attach the following
      boilerplate notice, with the fields enclosed by brackets "[]"
      replaced with your own identifying information. (Don't include
      the brackets!)  The text should be enclosed in the appropriate
      comment syntax for the file format. We also recommend that a
      file or class name and description of purpose be included on the
      same "printed page" as the copyright notice for easier
      identification within third-party archives.

   Copyright [yyyy] [name of copyright owner]

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.

### cargo-audit (the pinned audit binary)

`deps/pinned-binaries/cargo-audit` (v0.22.2) — the pinned advisory
audit tool. Licensed under MIT OR Apache-2.0 (its upstream metadata);
the MIT text is reproduced below, the Apache-2.0 text at
https://www.apache.org/licenses/LICENSE-2.0 (choosing either license
satisfies the dual grant).

#### MIT (the canonical text)

Permission is hereby granted, free of charge, to any person obtaining a
copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

### The RustSec advisory database snapshot

`deps/rustsec-advisory-db/` — the committed point-in-time snapshot
(the `advisory-db` tree-sha256 pin in `ci/pins.tsv`). Dedicated to the
public domain under CC0-1.0 (the upstream `LICENSE.txt`):

All code and data in the RustSec advisory database repository are dedicated to
the public domain (except otherwise specified, see exception below), and are
available under Creative Commons Zero 1.O Universal license (see
LICENSES/CC0-1.0.txt for terms).

By committing to this repository, you hereby waive all rights to the work
worldwide under copyright law, including all related and neighboring rights, to
the extent allowed by law.

You can copy, modify, distribute, and retransmit any information in this
repository, even for commercial purposes, without asking permission.

----

Exception: Additional content imported from the GitHub Security Advisory
("GHSA") database.

Additional content is adapted from GitHub Security Advisory, and is available
under Creative Commons Attribution 4.0 International (see
LICENSES/CC-BY-4.0.txt for terms).

Any such license and attribution will be explicitly covered, respectively in
the "license" and "url" (pointing to the advisory GHSA identifier prefixed by
https://github.com/advisories) metadata fields, directly within the applicable
advisories. As stated in the terms linked below, this fulfills the attribution
requirement.

https://docs.github.com/en/site-policy/github-terms/github-terms-for-additional-
products-and-features#advisory-database

## Third-party code in the source

### fastenc.rs (the shipped entropy engine)

`tool/src/fastenc.rs`: a clean-room reimplementation — no third-party
code. It uses the IJG public-domain Annex K.2 optimal-Huffman-table
algorithm (an algorithm, not a copyrighted expression) and cites the
independent Rust DNG CLI (LGPL 2.1) as a speed reference only.

## Committed test fixtures

The committed oracle + fuzz-corpus fixtures (`ci/oracle10/`,
`ci/oracle108/`, `ci/fuzz-corpus/**`) contain deterministic synthetic CFA
content in sanitized Sigma fp container templates. They are committed as
the byte-identity contract and released under the repository's MIT License.
The oracle source fixtures are deterministically regenerable by the
committed generator (`ci/fixture-templates/generate_fixtures.py`),
authenticated by the committed sha256 manifest
(`ci/fixture-templates/fixture-manifest.sha256`); the gate re-proves the
12/12 byte identity on every run.

## The Rust crate dependencies

The tool's lockfile contains 124 packages, including the tool root, per the
committed `tool/Cargo.lock`. The locked dependency set is audited against the
committed advisory snapshot by the ship gate on every run. These packages are
licensed per their crates.io metadata (the MIT / Apache-2.0 / BSD family;
the canonical texts at the SPDX/OSI URLs). No dependency imposes copyleft on
the built binary.
