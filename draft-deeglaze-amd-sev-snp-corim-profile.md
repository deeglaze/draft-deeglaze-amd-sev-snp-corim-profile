---
v: 3

title: CoRIM profile for AMD SEV-SNP attestation report
abbrev: CoRIM-SEV
docname: draft-deeglaze-amd-sev-snp-corim-profile-latest
category: std
consensus: true
submissiontype: IETF

ipr: trust200902
area: "Security"
workgroup: "Remote ATtestation ProcedureS"
keyword: RIM, RATS, attestation, verifier, supply chain

stand_alone: true
pi:
  toc: yes
  sortrefs: yes
  symrefs: yes
  tocdepth: 6

author:
- ins: D. Glaze
  name: Dionna Glaze
  org: Google LLC
  email: dionnaglaze@google.com

contributor:
- ins: Y. Deshpande
  name: Yogesh Deshpande
  organization: arm
  email: yogesh.deshpande@arm.com
  contribution: >
      Yogesh Deshpande contributed to the data model by providing advice about CoRIM founding principles.

normative:
  RFC3280:
  RFC4122:
  RFC5480:
  RFC5758:
  RFC8174:
  RFC8610: cddl
  RFC9334: rats-arch
  RFC9090: cbor-oids
  I-D.ietf-rats-corim: rats-corim
  X.690:
    title: >
      Information technology — ASN.1 encoding rules:
      Specification of Basic Encoding Rules (BER), Canonical Encoding
      Rules (CER) and Distinguished Encoding Rules (DER)
    author:
      org: International Telecommunications Union
    date: 2015-08
    seriesinfo:
      ITU-T: Recommendation X.690
    target: https://www.itu.int/rec/T-REC-X.690
  IANA.named-information: named-info

informative:
  SEV-SNP.API:
    title: SEV Secure Nested Paging Firmware ABI Specification
    author:
      org: Advanced Micro Devices Inc.
    seriesinfo: Revision 1.55
    date: September 2023
    target: https://www.amd.com/content/dam/amd/en/documents/epyc-technical-docs/specifications/56860.pdf
  GHCB:
    title: SEV-ES Guest-Hypervisor Communication Block Standardization
    author:
      org: Advanced Micro Devices Inc.
    seriesinfo: Revision 2.03
    date: July 2023
    target: https://www.amd.com/content/dam/amd/en/documents/epyc-technical-docs/specifications/56421.pdf
  SVSM:
    title: Secure VM Services Module
    author:
      org: Advanced Micro Devices Inc.
    seriesinfo: Revision 1.00
    date: July 2023
    target: https://www.amd.com/content/dam/amd/en/documents/epyc-technical-docs/specifications/58019.pdf
  VCEK:
    title: Versioned Chip Endorsement Key (VCEK) Certificate and KDS Interface Specification
    author:
      org: Advanced Micro Devices Inc.
    seriesinfo: Revision 0.51
    date: January 2023
    target: https://www.amd.com/content/dam/amd/en/documents/epyc-technical-docs/specifications/57230.pdf
  VLEK:
    title: Versioned Loaded Endorsement Key (VLEK) Certificate Definition
    author:
      org: Advanced Micro Devices Inc.
    seriesinfo: Revision 0.10
    date: October 2023
    target: https://www.amd.com/content/dam/amd/en/documents/epyc-technical-docs/user-guides/58369-010-versioned-loaded-endorsement-key-certificate-definition.pdf
  SEC1:
    title: >
      Standards for Efficient Cryptography Group (SECG), "SEC1: Elliptic Curve Cryptography"
    author:
      org: Certicom Corp.
    seriesinfo: Version 1.0
    date: September 2000
    target: https://www.secg.org/SEC1-Ver-1.0.pdf
  AMD.SPM:
    title: >
      AMD64 Architecture Programmer’s Manual, Volume 2: System Programming
    author:
      org: Advanced Micro Devices Inc.
    seriesinfo: Revision 3.42
    date: March 2024
    target: https://www.amd.com/content/dam/amd/en/documents/processor-tech-docs/programmer-references/24593.pdf

entity:
  SELF: "RFCthis"

--- abstract

AMD Secure Encrypted Virtualization with Secure Nested Pages (SEV-SNP) attestation reports comprise of reference values and cryptographic key material that a Verifier needs in order to appraise Attestation Evidence produced by an AMD SEV-SNP virtual machine.
This document specifies the information elements for representing SEV-SNP Reference Values in CoRIM format.

--- middle

# Introduction {#sec-intro}

TODO: write after content.

#  Conventions and Definitions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC2119] [RFC8174] when, and only when, they appear in all capitals, as shown here.

The reader is assumed to be familiar with the terms defined in {{-rats-corim}} and Section 4 of {{-rats-arch}}.
The syntax of data descriptions is CDDL as specified in {{-cddl}}.
Fields of the AMD SEV-SNP `ATTESTATION_REPORT` are referred to by their assigned names in [SEV-SNP.API].

# AMD SEV-SNP Attestation Reports

The AMD SEV-SNP attestation scheme in [SEV-SNP.API] contains measurements of security-relevant configuration of the host environment and the launch configuration of a SEV-SNP VM.
This draft documents the normative representation of attestation report Evidence as a CoRIM profile.

AMD-SP:
  AMD Secure Processor.
  A separate core that provides the confidentiality and integrity properties of AMD SEV-SNP.
  The function that is relevant to this document is its construction of signed virtual machine attestation reports.

VCEK:
  Versioned Chip Endorsement Key.
  A key for signing the SEV-SNP Attestation Report.
  The key is derived from a unique device secret as well as the security patch levels of relevant host components.

VLEK:
  Version Loaded Endorsement Key.
  An alternative SEV-SNP Attestation Report signing key that is derived from a secret shared between AMD and a Cloud Service Provider.
  The key is encrypted with a per-device per-version wrapping key that is then decrypted and stored by the AMD-SP.

VEK:
  Either a VCEK or VLEK.

## AMD SEV-SNP CoRIM Profile

AMD SEV-SNP launch endorsements are carried in one or more CoMIDs inside a CoRIM.

The profile attribute in the CoRIM MUST be present and MUST have a single entry set to the URI http://amd.com/please-permalink-me as shown in {{figure-profile}}.


~~~ cbor-diag
/ corim-map / {
  / corim.profile / 3: [
    32("http://amd.com/please-permalink-me")
  ]
  / ... /
}
~~~
{: #figure-profile title="SEV-SNP attestation profile version 1, CoRIM profile" }

### AMD SEV-SNP Target Environment

The `ATTESTATION_REPORT` structure as understood in the RATS Architecture [RFC9334] is a signed collection of Claims that constitute Evidence about the Target Environment.
The Attester for the `ATTESTATION_REPORT` is specialized hardware that will only run AMD-signed firmware.

The `class-id` for the Target Environment measured by the AMD-SP is the tagged OID `#6.111(1.3.6.1.4.1.3704.2.1)`.
The launched VM on SEV-SNP has an ephemeral identifier `REPORT_ID`.
If the VM is the continuation of some instance as carried by a migration agent, there is also a possible `REPORT_ID_MA` value to identify the instance.
The attester, however, is always on the same `CHIP_ID`.
Given that the `CHIP_ID` is not uniquely identifying for a VM instance, it is better classified as a group.
The `CSP_ID` is similarly better classified as a group.
Either the `CHIP_ID` or the `CSP_ID` may be represented in the `group` codepoint as a tagged-bytes.
If the `SIGNING_KEY` bit of the attestation report is 1, then the `group` MUST be the `CSP_ID` of the VLEK.

~~~ cbor-diag
/ environment-map / {
  / class-map / {
    / class-id: / 0 => #6.111(1.3.6.1.4.1.3704.2.1)
  }
  / instance: / 1 => #6.563({
    / report-id: / 0 => REPORT_ID,
    / report-id-ma: / 1 => REPORT_ID_MA
    })
  / group: / 2 => #6.560(CHIP_ID)
}
~~~

### AMD SEV-SNP Attestation Report measurements

The fields of an attestation report are named by `mkey` numbers that map to appropriate `measurement-values-map` values.
This profile defines no new `measurement-values-map` extensions for the `$$measurement-values-map-extensions` socket.
The only extensions are to `$$flags-map-extensions`.

The VMPL field is a raw `0..3` value, so this profile extends the raw value type choice of the CoRIM base CDDL:

~~~ cddl
{::include cddl/sevsnpvm-vmpl-raw-value-ext.cddl}
~~~

#### AMD SEV-SNP `flags-map` extensions

The `GUEST_POLICY` field and the `PLATFORM_INFO` field of the attestation report contain flags distinguished from the base CoRIM CDDL.

The `GUEST_POLICY` boolean flags are added as extensions to `$$flags-map-extension`, starting from codepoint -1.

~~~ cddl
{::include cddl/sevsnpvm-guest-policy-flags-ext.cddl}
~~~

There are 47 available bits for selection when the mandatory 1 in position 17 and the ABI Major.Minor values are excluded from the 64-bit `GUEST_POLICY`.
The `PLATFORM_INFO` bits are host configuration that are added as extensions to `$$flags-map-extension` starting at `-49`.

~~~ cddl
{::include cddl/sevsnphost-platform-info-flags-ext.cddl}
~~~

The `sevsnpvm-policy-debug-allowed` flag is redundant with `flags-map / is-debug`, so either representation is valid.
The entirety of the value space is reserved for AMD revisions to the SEV-SNP firmware and corresponding ATTESTATION_REPORT API.

#### Version scheme extension {#sec-version-scheme}

Extend the `$version-scheme` type with as follows

~~~ cddl
{::include cddl/sevsnpvm-version-scheme-ext.cddl}
~~~

The `-1` scheme is a string representation of the two 128-bit identifiers in hexadecimal encoding as separated by `/`.
The scheme allows for fuzzy comparison with `_` as a wildcard on either side of the `/`.

An endorsement provider MAY use a different version scheme for the `&(version: 0)` codepoint.

#### AMD SEV-SNP `mkey`s

The measurements in an ATTESTATION_REPORT are grouped into 7 `mkey`s.

* `0`: The GUEST measurements for  `FAMILY_ID` and `IMAGE_ID` as `&(version: 0)`,`GUEST_SVN` as `&(svn: 1)`, `MEASUREMENT` in `&(digests: 2)`, `POLICY` flags in `&(flags: 3)`.
* `1`: The VMPL of the report as a `&(raw-value: 5)`.
* `2`: The HOST measurements for `CURRENT_BUILD`, `CURRENT_MAJOR`, and `CURRENT_MINOR` as `&(version: 0)`, `CURRENT_TCB` as `&(svn: 1)`, `HOSTDATA` as `&(raw-value: 5)`, `PLATFORM_INFO` flags in `&(flags: 3)`
* `3`: The COMMITTED host measurements for `COMMITTED_BUILD`, `CURRENT_MAJOR`, and `CURRENT_MINOR` as `&(version: 0)`, `COMMITTED_TCB` as `&(svn: 1)`.
* `4`: The LAUNCH_TCB host measurement as `&(svn: 1)`.
* `5`: The REPORTED_TCB host measurement as `&(svn: 1)`.
* `6`: The MINIMUM_ABI guest measurement for `POLICY`'s lower 16 bits `MAJOR_ABI` and `MINOR_ABI` as `&(version: 0)`.

The `REPORT_DATA` is meant for protocol use and not reference measurements.
The `REPORT_ID` and `REPORT_ID_MA` are accounted for in the `environment-map`'s instance field.
The `MAJOR_ABI`, `MINOR_ABI` of the `POLICY` are not entirely redundant with Verifier policy evaluation against the `HOST`'s `&(version: 0)` since the policy may relevant to key derivations.

#### Notional Instance Identity {#sec-id-tag}

A CoRIM instance identifier is universally unique, but there are different notions of identity within a single attestation report that are each unique within their notion.
A notional instance identifier is a tagged CBOR map from integer codepoint to opaque bytes.

~~~ cddl
{::include cddl/int-bytes-map.cddl}
~~~

Profiles may restrict which integers are valid codepoints, and may restrict the respective byte string sizes.
For this profile, only codepoints 0 and 1 are valid.
The expected byte string sizes are 32 bytes.
For the `int-bytes-map` to be an interpretable extension of `$instance-id-type-choice`, there is `tagged-int-bytes-map`:

~~~ cddl
{::include cddl/tagged-int-bytes-map.cddl}
~~~

### AMD SEV-SNP Evidence Translation

The `ATTESTATION_REPORT` Evidence is converted into a CoRIM `endorsed-triple-record` using the rules in this section.
If the `ATTESTATION_REPORT` contains `ID_BLOCK` information, the relevant fields will be represented in a second `endorsed-triple-record` with a different `authorized-by` field value, as per the merging rules of {{-rats-corim}}.
An `ATTESTATION_REPORT` does not contain an `ID_BLOCK` if the `ID_KEY_DIGEST` field is all zeros.

#### `environment-map`

*  The `environment-map / class / class-id` field SHALL be set to the BER {{X.690}} encoding of OID {{-cbor-oids}} `1.3.6.1.4.1.3704.2.1` and tagged with #6.111.
*  The `environment-map / instance ` field SHALL be set to an `int-bytes-map` tagged with #6.111 with at least one codepoint 0 or 1.
   If codepoint 0 is populated, it SHALL be set to `REPORT_ID`.
   If codepoint 1 is populated, it SHALL be set to `REPORT_ID_MA`.
*  The `environment-map / group ` field SHALL be set to the VLEK `csp_id` and tagged with #6.111 if `SIGNING_KEY` is 1.
   If `SIGNING_KEY` is 0, the field MAY be set to the VCEK `hwid` and tagged with #6.111.

#### `measurement-map`

Different fields of the attestation report correspond to different `mkey`s.
For each, the `authorized-by` key SHALL be set to a representation of the VEK that signed the `ATTESTATION_REPORT`, or a key along the certificate path to a self-signed root, i.e., the ASK, ASVK, or ARK for the product line.

The translation makes use of the following metafunctions:

*  The function `is-set(x, b)` represents whether the bit at position `b` is set in the number `x`.
*  The function `hex(bstr)` represents the hexadecimal string encoding of a byte string.
*  The function `dec(b)` represents a byte in its decimal string rendering.
*  The function `leuint(bstr)` represents the translation of a byte string into a CBOR `uint` using a little-endian interpretation.

Juxtaposition of expressions with string literals is interpreted with string concatenation.

Note: A value of `0` is not treated the same as unset given the semantics for matching `flags-map`.

* `/ mkey: / 0`, the guest data
  +  The `&(version: 0)` codepoint MAY be unset if the report does not contain `ID_BLOCK` data, otherwise the `&(version: 0)` codepoint SHALL be set to `/ version-map / { / version: / 0: vstr / version-scheme: / 1: -1 }` with version string `vstr` constructed as `hex(FAMILY_ID) '/' hex(IMAGE_ID)`.
  +  The `&(svn: 1)` codepoint MAY be unset if the report dos not contain `ID_BLOCK` data, otherwise the `&(svn: 1)` codepoint SHALL be set to `552(leuint(GUEST_SVN))`.
  +  The `&(digests: 2)` codepoint SHALL be set to `[ / digest / [ / alg: / 7, / val: / MEASUREMENT ] ]`.
  +  The `&(flags: 3) / flags-map / is-confidentiality-protected` codepoint MAY be set to true.
  +  The `&(flags: 3) / flags-map / is-integrity-protected` codepoint MAY be set to true.
  +  The `&(flags: 3) / flags-map / is-replay-protected` codepoint MAY be set to true.
  +  The `&(flags: 3) / flags-map / sevsnpvm-policy-smt-allowed` codepoint SHALL be set to `is-set(GUEST_POLICY, 16)`.
  +  The `&(flags: 3) / flags-map / sevsnpvm-policy-migration-agent-allowed` codepoint SHALL be set to `is-set(GUEST_POLICY, 18)`.
  +  One or both of `&(flags: 3) / flags-map / sevsnpvm-policy-debug-allowed` and `is-debug` codepoints SHALL be set to `is-set(GUEST_POLICY, 19)`.
  +  The `&(flags: 3) / flags-map / sevsnpvm-policy-single-socket-only` codepoint SHALL be set to `is-set(GUEST_POLICY, 20)`.
  +  The `&(flags: 3) / flags-map / sevsnpvm-policy-cxl-allowed` codepoint SHALL be set to `is-set(GUEST_POLICY, 21)`.
  +  The `&(flags: 3) / flags-map / sevsnpvm-policy-mem-aes-256-xts-required` codepoint SHALL be set to `is-set(GUEST_POLICY, 22)`.
  +  The `&(flags: 3) / flags-map / sevsnpvm-policy-rapl-must-be-disabled` codepoint SHALL be set to `is-set(GUEST_POLICY, 23)`.
  +  The `&(flags: 3) / flags-map / sevsnpvm-policy-ciphertext-hiding-must-be-enabled` codepoint SHALL be set to `is-set(GUEST_POLICY, 24)`.
  +  Any further non-reserved bit position `b` of `POLICY` as the API evolves will be set at `flags-map` codepoint `16-b`.
  * `/ mkey: / 6`, the `&(version: 0)` SHALL be set to `/ version-map / { / version: /: POLICY[15:8] '.' POLICY[7:0] '.0' , / version-scheme: / 16384 }` where the `POLICY` slices are translated to decimal number strings and juxtaposition is string concatenation.
* `/ mkey: 1 /` the report privilege level
  + The `&(raw-value: 5)` codepoint SHALL be set to `VMPL` as a `uint`.
* `/ mkey: 2 /` the current host info
  + The `&(version: 0)` codepoint SHALL be set to `/ version-map / { / version: 0 / vstr / version-scheme: / 1: 16384 }` with version string `vstr` constructed as `dec(CURRENT_MAJOR) '.' dec(CURRENT_MINOR) '.' dec(CURRENT_BUILD)`.
  + The `&(flags: 3) / flags-map / sevsnphost-smt-enabled` codepoint SHALL be set to `is-set(PLATFORM_INFO, 0)`
  + The `&(flags: 3) / flags-map / sevsnphost-tsme-enabled` codepoint SHALL be set to `is-set(PLATFORM_INFO, 1)`
  + The `&(flags: 3) / flags-map / sevsnphost-ecc-mem-reported-enabled` codepoint SHALL be set to `is-set(PLATFORM_INFO, 2)`
  + The `&(flags: 3) / flags-map / sevsnphost-rapl-disabled` codepoint SHALL be set to `is-set(PLATFORM_INFO, 3)`
  + The `&(flags: 3) / flags-map / sevsnphost-ciphertext-hiding-enabled` codepoint SHALL be set to `is-set(PLATFORM_INFO, 4)`
  + Any further non-reserved bit position `b` of `PLATFORM_INFO` will be set at `flags-map` codepoint `-1-b`.
  + The `&(raw-value: 5)` codepoint SHALL be set to `560(HOSTDATA)` and MAY be omitted if all zeros.
* `/ mkey: 3 /` the committed host info
  + The `&(svn: 1)` codepoint SHALL be set to `552(leuint(COMMITTED_TCB))`.
* `/ mkey: 4 /` the launch tcb
  + The `&(svn: 1)` codepoint SHALL be set to `552(leuint(LAUNCH_TCB))`.
* `/ mkey: 5 /` the reported tcb
  + The `&(svn: 1)` codepoint SHALL be set to `552(leuint(REPORTED_TCB))`.
* `/ mkey: 6 /` the guest policy's minimum SEV-SNP ABI version that launch compares against `CURRENT_MAJOR` and `CURRENT_MINOR`.
  + The `&(version: 0)` codepoint SHALL be set to `/ version-map / { / version: / 0: vstr / version-scheme: / 1: 16384 }` with version string `vstr` constructed as `dec(MAJOR_ABI) '.' dec(MINOR_ABI) '.0'`.

If `ID_BLOCK` information is available, it appears in its own `endorsement-triple-record` with additional values in `authorized-by` beyond the attestation key.
The `authorized-by` field is extended with `32780(ID_KEY_DIGEST)`, and if `AUTHOR_KEY_EN` is 1, then it is also extended with `32780(AUTHOR_KEY_DIGEST)`.
The Verifier MAY use a base CDDL CoRIM `$crypto-key-type-choice` representation if its public key information's digest compares equal to the #6.32780-tagged bytes, as described in {{sec-key-digest}}.

#### Key digest comparison {#sec-key-digest}

When `ID_BLOCK` is used, the full key information needed for signature verification is provided by the VMM at launch in an `ID_AUTH` structure.
The SNP firmware verifies the signatures and adds digests of the signing key(s) to the attestation report as evidence of successful signature verification.
When a Verifier does not have access to the original public key information used in `ID_AUTH`, the attestation report key digests can still be used as a representation of authority.

The APPENDIX: Digital Signatures section of [SEV-SNP.API] specifies a representation of public keys and signatures.
An attestation report key digest will be a SHA-384 digest of the 0x403 byte buffer representation of a public key.
If an author key is used, its signature of the ID_KEY is assumed to exist and have passed given the SNP firmware specification.

If a `$crypto-key-type-choice` key representation specifies an algorithm and parameters that are included in the Digital Signatures appendix, it is comparable to a #6.32780-tagged byte string.

*  Two #6.32780-tagged byte strings match if and only if their encodings are bitwise equal.
*  A thumbprint representation of a key is not comparable to a #6.32780-tagged byte string since the parameters are not extractable.
*  A PKIX public key (#6.554-tagged `tstr`) or PKIX certificate (#6.555-tagged `tstr`) MAY be comparable to a #6.32780-tagged byte string.

The [RFC3280] specified `AlgorithmIdentifier` has optional parameters based on the algorithm identifier.
The AMD signature algorithm `1h` corresponds to algorithm `ecdsa-with-sha384` from section 3.2 of [RFC5758], but the parameters MUST be omitted.
The `SubjectPublicKeyInfo` is therefore `id-ecPublicKey` from section 2.1.1 of [RFC5480] to further allow the curve to be specified, despite not further specifying that the signature is of a SHA-384 digest.
The AMD ECSDA curve name `2h` corresponds to named curve `secp384r1` from section 2.2 of [RFC5480].
The `ECPoint` conversion routines in section 2 of [SEC1] provide guidance on how the `QX` and `QY` little-endian big integers zero-padded to 72 bytes may be constructed.

## AMD SEV-SNP Launch Event Log {#sec-launch-config}

The composition of a SEV-SNP VM may be comprised of measurements from multiple principals, such that no one principal has absolute authority to endorse the overall measurement value represented in the attestation report.
If one principal does have that authority, the `ID_BLOCK` mechanism provides a convenient launch configuration endorsement mechanism without need for distributing a CoRIM.
This section documents an event log format the Virtual Machine Monitor (VMM) may construct at launch time and provide in the data pages of an extended guest request, as documented in [GHCB].

The content media type shall be `application/vnd.amd.sev.snp.launch-config.v1+cbor` for the encoding of a `sevsnp-launch-configuration-map`:

~~~ cddl
{::include cddl/sevsnp-launch-configuration-map.cddl}
~~~

*  The `fms` field if included SHALL contain the `CPUID[1]_EAX` value masked with `0x0fff3fff` to provide chip family, model, stepping information.
  If not included, the Verifier may reference the VEK certificate's extension for `productName`.
*  The `sevsnpvm-launch-baseline` field if not included is SHALL be interpreted as an all zero SHA-384 digest.
The calculation of the launch measurement SHALL use the value is the initial `PAGE_INFO`'s `DIGEST_CUR` value.
*  The `sevsnpvm-launch-updates` field contains an ordered list of inputs to the `SNP_LAUNCH_UPDATE` command:

~~~ cddl
{::include cddl/sevsnp-launch-update-sequence.cddl}
~~~

The `sevsnp-launch-update-data-map` contains all fields of the `PAGE_INFO` structure that are needed for reconstructing a measurement.
If an update repeats many times, such as an application processor VMSA, then that can be compressed with the `repeat` field.

The content codepoint MUST NOT be present if the page type is neither `PAGE_TYPE_NORMAL` (01h) nor `PAGE_TYPE_VMSA` (02h).

For the VMM, there are some updates it does on behalf of a different principal than the firmware vendor, so it may choose to pass through some of the information about the launch measurement circumstances for separate appraisal.

The encoded `sevsnp-launch-configuration-map` may be found in the extended guest report data table for UUID `8dd67209-971c-4c7f-8be6-4efcb7e24027`.

The VMM is expected to provide all fields unless their default corresponds to the value used.

### VMSA evidence {#vmsa-evidence}

The VMM that assembles the initial VM state is also responsible for providing initial state for the vCPUs.
The vCPU secure save area is called the VMSA on SEV-ES.
The VMSA initial values can vary across VMMs, so it's the VMM provider's responsibility to sign their reference values.

The reset vector from the firmware also influences the VMSAs for application processors' `RIP` and `CS_BASE`, so the VMSA is not entirely determined by the VMM.
The digest alone for the VMSA launch update command is insufficient to represent the separately specifiable reference values when the GHCB AP boot protocol is not in use.

The bootstrap processor (BSP) and application processors (APs) typically have different initial values.
The APs typically all have the same initial value, so the `ap-vmsa` codepoint MAY be a single `sevsnp-vmsa-type-choice` to represent its replication.
Alternatively, each AP's initial VMSA may be individually specified with a list of `sevsnp-vmsa-type-choice`.

~~~ cddl
{::include cddl/sevsnp-repeated-vmsa.cddl}
~~~

All VMSA fields are optional.
A missing VMSA field in evidence is treated as its default value.
A missing VMSA field in a reference value is one less matching condition.

### VMSA default values


Unless otherwise stated, each field's default value is 0.
The [AMD.SPM] is the definitive source of initial state for CPU registers, so any default value in this specification that diverges is a flaw but still MUST be considered the default for a missing value.
Figure {{figure-vmsa-defaults}} is a CBOR representation of the nonzero default values that correspond to initial CPU register values as of the cited revision's Table 14-1.


~~~ cbor-diag
/ sevsnp-vmsa-map-r1-55 / {
  / es: / 0 => / svm-vmcb-seg-map / {
    / attrib: / 1 => 0x92
    / limit: / 2 => 0xffff
  }
  / cs: / 1 => / svm-vmcb-seg-map / {
    / selector: / 0 => 0xf000
    / attrib: / 1 => 0x9b
    / limit: / 2 => 0xffff
    / base: / 3 => 0xffff0000
  }
  / ss: / 2 => / svm-vmcb-seg-map / {
    / attrib: / 1 => 0x92
    / limit: / 2 => 0xffff
  }
  / ds: / 3 => / svm-vmcb-seg-map / {
    / attrib: / 1 => 0x92
    / limit: / 2 => 0xffff
  }
  / fs: / 4 => / svm-vmcb-seg-map / {
    / attrib: / 1 => 0x92
    / limit: / 2 => 0xffff
  }
  / gs: / 5 => / svm-vmcb-seg-map / {
    / attrib: / 1 => 0x92
    / limit: / 2 => 0xffff
  }
  / gdtr: / 6 => / svm-vmcb-seg-map / { / limit: / 2 => 0xffff }
  / ldtr: / 7 => / svm-vmcb-seg-map / {
    / attrib: / 1 => 0x82
    / limit: / 2 => 0xffff
  }
  / idtr: / 8 => / svm-vmcb-seg-map / { / limit: / 2 => 0xffff }
  / tr: / 9 => / svm-vmcb-seg-map / {
    / attrib: / 1 => 0x83
    / limit: / 2 => 0xffff
  }
  / cr0: / 33 => 0x10
  / dr7: / 34 => 0x400
  / dr6: / 35 => 0xffff0ff0
  / rflags: / 36 => 0x2
  / rip: / 37 => 0xfff0
  / g_pat: / 63 => 0x7040600070406
  / sev_features: / 91 => 0x1
  / xcr0: / 97 => 0x1
  / mxcsr: / 99 => 0x1f80
  / x87_ftw: / 100 => 0x5555
  / x87_fcw: / 102 => 0x40
}
~~~
{: #figure-vmsa-defaults title="SEV-SNP default VMSA values" }

The `rdx` is expected to be the FMS of the chip and SHOULD match the `fms` field of the `sevsnp-launch-configuration-map`.
A VMM provider may sign reference values for a `sevsnp-launch-configuration-map` to specify just the non-default values for the BSP and AP state.

Note: This is the RESET state, not the INIT state.

The `sev_features` codepoint is not a typical AMD64 INIT state, but specifies that SEV-SNP is in use for the virtual CPU.

#### Example VMM reference values for VMSA

Qemu, AWS Elastic Compute Cloud (EC2), and Google Compute Engine (GCE), all use KVM, which initializes `cr4` and `efer` to non-default values.
The values for `cr4` and `efer` are different from the SPM to allow for `PSE` (page size extension) `SVME` (secure virtual machine enable).

Only Qemu follows the [AMD.SPM] specification for `rdx`, which is to match the family/model/stepping of the chip used.
GCE provides an `rdx` of `0x600` regardless (following the Intel spec), and EC2 provides `0` regardless.
GCE sets the `G_PAT` (guest page attribute table) register to `0x70406` to disable PA4-PA7.
Both Qemu and GCE set the `tr` attrib to `0x8b`, so it starts as a busy 32-bit TSS instead of the default 16-bit.
GCE sets `ds`, `es`, `fs`, `gs`, and `ss` attributes to `0x93` since that's the initial state on Intel processors and that works fine too.

Qemu uses the Intel INIT state for the x87 floating point control word (0x37f), but 0 for the x87 floating point tag word.

## AMD SEV-SNP Launch Event Log Appraisal

The `sevsnp-launch-configuration-map` is translated into a full sequence of `SNP_LAUNCH_UPDATE` commands on top of a baseline digest value to calculate following [SEV-SNP.API]'s documentation of digest calculation from `PAGE_INFO` structures.

The first `PAGE_INFO` structure uses the baseline digest as its `DIGEST_CUR`.
The following pseudocode for the function measurement computes the expected measurement of the endorsement format.
If this measurement equals the digests value with VCEK authority, then add the baseline and updates measurement values to the same ECT as the attestation report.

Since the VMM only has to provide the gpa, page type, and digest of the contents, the rest of the fields of a `sevsnp-launch-update-data-map` have default values when translated to a `PAGE_INFO` without the `DIGEST_CUR` field.
If the baseline is not provided, it is assumed to be all zeros.

~~~
measurement({fms, base, updates, bsp, aps}) = iterate(base, infos)
  where infos = update-info ++ [bsp-info] ++ ap-info
        update-info = appendmap(mk_page_info(fms), updates)
        bsp-info = mk_vmsa_info(fms)(bsp)
        ap-info = mk_ap_vmsa_info(fms, aps)
~~~

The `iterate` function is applies a `sha384` digest update operation on all given `PAGE_INFO` byte strings:

~~~
iterate(digest_cur, []) = digest_cur
iterate(digest_cur, info:infos) = iterate(digest_next , infos)
  where digest_next = sha384(digest_cur || sha384(info))
~~~

The `appendmap` function combines the list results of mapping a function over a list by appending them:

~~~
appendmap(f, []) = []
appendmap(f, x:xs) = append(f(x), appendmap(f, xs))
~~~

### Updates as `PAGE_INFO` without `DIGEST_CUR`.

The `mk_page_info` function translates update components into a singleton list of their `PAGE_INFO` byte string form:

~~~
mk_page_info(fms)({page-type or PAGE_TYPE_NORMAL,
                   contents,
                   gpa,
                   page-data or 0,
                   vmpl-perms or 0}):list[bytes] = [
  contents || {0x70, 0, page-type, page-data} ||
  leuint64(vmpl-data) || leuint64(gpa),
]
~~~

The `leuint64` function translates a 64-bit unsigned integer into its little endian byte string representation.

### VMSAs as `PAGE_INFO` without `DIGEST_CUR`.

The `bsp-vmsa` will always be measured.
If the VMM does not provide it, the default values will be used.
If the `$sevsnp-vmsa-type-choice` is a `uuid-type` or `oid-type`, the `PAGE_INFO` fields are "well-known" as published by an entity claiming the identifier.
The well-known values are expected to be provided by the Verifier in accordance with the associated published values.

If the `$sevsnp-vmsa-type-choice` is a `tagged-sevsnp-vmsa-map-r1-55`, then its `PAGE_INFO` byte string is to be defined as follows:

~~~
mk_vmsa_info(fms)(#6.32781(sevsnp-vmsa-map-r1-55)) =
  sha384(to_vmsa_page(sevsnp-vmsa-map-r1-55)) ||
  {0x70, 0, 0x2, sevsnp-vmsa-map-r1-55 / page-data} ||
  leuint64(sevsnp-vmsa-map-r1-55 / vmpl-perms) ||
  initial_vmsa_gpa
~~~

The `initial_vmsa_gpa` is the little-endian representation of a high memory address that is last page on an architecture with 48-bit width addresses: `{0x00, 0xF0, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00}`

The `to_vmsa_page` function constructs a VMSA 4KiB page with fields written to their respective locations as specified by the [AMD.SPM].
Fields not represented in the map are taken to be their default value from figure {{figure-vmsa-defaults}}.

The `ap-vmsa` will be measured only if present.
The list of VMSA type choices is translated to a list of `PAGE_INFO` with the same operation:

~~~
mk_ap_vmsa_info(fms, [ + sevsnp-vmsa-type-choice ]) =
  map(mk_vmsa_info(fms)([ sevsnp-vmsa-type-choice ... ])
~~~

The repeated vmsas expand into a list of the same `PAGE_INFO` byte string repeated:

~~~
mk_ap_vmsa_info(fms, #6.32872([vmsa, repeat])) =
  [mk_vmsa_info(fms)(vmsa)]*repeat
~~~

### Comparisons for reference values

An "any" sequence number matches any sequence number.
The uint sequence number starts counting after the baseline matches.
If there is no reference baseline, the sequence numbers start at 0.
If there is a reference baseline, the VMM's provided baseline gets hash-combined with the provided updates until the digest equals the signed baseline, and the sequence numbers s
tart from the following update as if they are 1.
If there is no update that leads to a matching baseline value, no updates match.

The other `sevsnp-launch-update-data-map` codepoints must match all present codepoints with encoding equality.
The evidence ECT for the matching values are then split into a separate ECT to account for the added authority.

Note: the VMM may split its baseline and updates at any point, which will drop the specificity of individual updates.
The individual updates of a reference value MUST match individual updates from the VMM.
It is therefore advantageous to combine as many updates in the reference value into the baseline as is feasible.

### Example: OVMF with `SevMetadata`

The Open Virtual Machine Firmware project directs the VMM to not just load the UEFI at the top of the 4GiB memory range, but also measure referenced addresses with particular `SNP_LAUNCH_UPDATE` inputs.
Given that the firmware may be built by one party, the VMM another, and `SEV_KERNEL_HASHES` data yet another, the different data spread across the `SNP_LAUNCH_UPDATE` commands should be signed by the respective parties.

#### OVMF data

The GUID table at the end of the ROM is terminated by the GUID `96b582de-1fb2-45f7-baea-a366c55a082d` starting at offset `ROM_end - 0x30`.
At offset `ROM_end - 0x32` there is a length in a 16-bit little endian unsigned integer.
At offset `ROM_end - 0x32 - length` there is a table with format

| Type | Name |
| ---- | ---- |
| * | * |
| `UINT8[Length]` | Data |
| `LE_UINT16` | Length |
| `EFI_GUID` | Name |
{: title="OVMF footer GUID table type description"}

`LE_UINT16` is the type of a little endian 16-bit unsigned integer.
`EFI_GUID` is the UUID format specified in section 4 of [RFC4122].
The footer GUID and length specifies the length of the table of entries itself, which does not include the footer.

Within this table there is an entry that specifies the guest physical address that contains the `SevMetadata`.

| Type | Name |
| ---- | ---- |
| `LE_UINT32` | Address |
| `LE_UINT16` | Length |
| `EFI_GUID` | dc886566-984a-4798-A75e-5585a7bf67cc |
{: title="SevMetadataOffset GUID table entry description"}

At this address when loaded, or at offset `ROM_end - (4GiB - Address)`, the `SevMetadata`,

| Type | Name |
| ---- | ---- |
| `LE_UINT32` | Signature |
| `LE_UINT32` | Length |
| `LE_UINT32` | Version |
| `LE_UINT32` | NumSections |
| `SevMetadataSection[Sections]` | Sections |
{: title="SevMetadata type description" }

The `Signature` value should be `'A', 'S', 'E', 'V'` or "VESA" in big-endian order: `0x56455341`.
Where `SevMetadataSection` is

| Type | Name |
| ---- | ---- |
| `LE_UINT32` | Address |
| `LE_UINT32` | Length |
| `LE_UINT32` | Kind |
{: title="SevMetadataSection type description"}

A section references some slice of guest physical memory that has a certain purpose as labeled by `Kind`:

| Value | Name | PAGE_TYPE |
| ----- | ---- | --------- |
| 1 | OVMF_SECTION_TYPE_SNP_SEC_MEM | PAGE_TYPE_UNMEASURED |
| 2 | OVMF_SECTION_TYPE_SNP_SECRETS | PAGE_TYPE_SECRETS |
| 3 | OVMF_SECTION_TYPE_CPUID | PAGE_TYPE_CPUID |
| 4 | OVMF_SECTION_TYPE_SNP_SVSM_CAA | PAGE_TYPE_ZERO |
| 16 | OVMF_SECTION_TYPE_KERNEL_HASHES | PAGE_TYPE_NORMAL |
{: title="OVMF section kind to SEV-SNP page type mapping"}

The memory allocated to the initial UEFI boot phase, `SEC`, is unmeasured but must be marked for encryption without needing the `GHCB` or `MSR` protocol.
The `SEC_MEM` sections contain the initial `GHCB` pages, page tables, and temporary memory for stack and heap.
The secrets section is memory allocated specifically for holding secrets that the AMD-SP populates at launch.
The cpuid section is memory allocated to the CPUID source of truth, which shouldn't be measured for portability and host security, but should be verified by AMD-SP for validity.
The [SVSM] calling area address section is to enable the firmware to communicate with a secure VM services module running at VMPL0.
The kernel hashes section is populated with expected measurements when boot advances to load Linux directly and must fail if the disk contents' digests disagree with the measured hashes.

The producer of the OVMF binary may therefore decide to sign a verbose representation or a compact representation.
A verbose representation would have hundreds of updates given that every 4KiB page must be represented.
For an initial example, consider the 2MiB OVMF ROM's 512 4KiB updates as the baseline, and the metadata as individual measurements afterwards.

~~~ cbor-diag
{::include cddl/examples/ovmf-verbose.diag}
~~~

In this example the SEV-ES reset vector is located at `0x80b004`.
The AP RIP is the lower word and the CS_BASE is the upper word.
The first unmeasured section is for the SEC stage page tables up to GHCB at address `0x800000`, which has 9 pages accounted for in sequence.
The second unmeasured section is for the GHCB page up to secrets at address `0x80A000`, which has 3 pages accounted for in sequence.
The secrets page is at address `0x80D000`.
The CPUID page is at address `rx80E000`.
The svsm calling area page address is `0x80F000`.
The launch secrets and kernel hashes are at address `0x810000` and fit in 1 page.
The location of the final unmeasured pages are for the APIC page tables and PEI temporary memory.
The final section after the svsm calling area and kernel hashes up to the PEI firmware volume base, so `0x811000` up to `0x820000` for another 15 pages.

A more compact representation can take advantage of the fact that several of the first update commands are driven entirely by the firmware.
The firmware author may then decide to reorder the section processing to ensure the kernel hashes are last, as there is no requirement for sequential GPAs.
The baseline contains the initial ROM plus all the sections that don't have a dependency on external measured information.
Thanks to the section reordering, only the `SEV_KERNEL_HASHES` need to be called out in the signed configuration.

~~~ cbor-diag
{::include cddl/examples/ovmf-compact.diag}
~~~

#### Kernel data

The OVMF image may be provided by a different vendor than the OS disk image.
The user of the VM platform may not have direct access to reference values ahead of time to countersign their combination.
The kernel hashes become an input to the control plane that are then fed to the construction of the VM launch.
The provider of the OS disk image then is responsible for signing the reference values for kernel hashes.
The order in which kernel hashes are loaded, and at which address is irrelevant provided the attestation policy requires some signed value in the end, so the signer does not provide either the `gpa` or `seq-no` values.

~~~ cbor-diag
{::include cddl/examples/kernel-hashes.diag}
~~~

The digest is of a Qemu data structure that contains different digests of content from the command line.

# IANA Considerations

## New CBOR Tags

IANA is requested to allocate the following tags in the "CBOR Tags" registry {{!IANA.cbor-tags}}.
The choice of the CoRIM-earmarked value is intentional.

| Tag   | Data Item | Semantics                                                                             | Reference |
| ---   | --------- | ---------                                                                             | --------- |
| 563   | `map`     | Keys are always int, values are opaque bytes, see {{sec-id-tag}}                      | {{&SELF}} |
| 32780 | `bytes`   | A digest of an AMD public key format that compares with other keys {{sec-key-digest}} | {{&SELF}} |
| 32781 | `map`   | A map of virtual machine vCPU registers (VMSA) to initial values {{vmsa-evidence}} | {{&SELF}} |
| 32782 | `array`   | A record of a single VMSA and a count of how many times it repeats {{vmsa-evidence}} | {{&SELF}} |
{: #cbor-tags title="Added CBOR tags"}

## New media types

### `application/vnd.amd.sev.snp.launch-config.v1+cbor`

Described in {{sec-launch-config}}.

### `application/vnd.amd.sev.snp.attestation-report`

An octet-stream that is expected to be interpreted as an AMD SEV-SNP ATTESTATION_REPORT.

### `application/vnd.amd.ghcb.guid-table`

An octet-stream that follows the [GHCB]'s GUID table ABI, recounted here.
A GUID table is a header followed by an octet-stream body.
The header is a sequence of entries described in {{guid_table_entry}} terminated by an all zero entry.
After the all zero entry are the bytes that the header entries index into.

| Type | Name | Description |
| ---- | ---- |
| `UUID` | GUID | An [RFC4122] byte format UUID |
| `LE_UINT32` | Offset | A little-endian offset into the body |
| `LE_UINT32` | Length | A little-endian byte length of the span |
{: #guid_table_entry title="guid_table_entry type description"}

A header entry is valid if its Offset+Length is less than or equal to the body size.

--- back

# CoRIM Extensions CDDL {#sec-corim-cddl}

~~~ cddl
{::include cddl/corim-autogen.cddl}
~~~
