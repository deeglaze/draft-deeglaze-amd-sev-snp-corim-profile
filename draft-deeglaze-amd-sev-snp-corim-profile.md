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

entity:
  SELF: "RFCthis"

--- abstract

AMD Secure Encrypted Virtualization with Secure Nested Pages (SEV-SNP) attestation reports comprise of reference values and cryptographic key material that a Verifier needs in order to appraise Attestation Evidence produced by an AMD SEV-SNP virtual machine.
This document specifies the information elements for representing SEV-SNP Reference Values in CoRIM format.

--- middle

# Introduction {#sec-intro}

This profile describes the extensions and restrictions placed on Reference Values, Endorsements, and Evidence that support the attestation capabilities of AMD products that provide Securet Encrypted Virtualization with Secure Nested Pages (SEV-SNP).

CoRIM ({{-rats-corim}}) defines a baseline CDDL for Reference Values and Endorsements that this profile extends.
Some measurement types of the baseline CDDL are not used in this profile.
The AMD SEV-SNP attestation report byte format is specified by AMD.
The profile defines a transformation from the AMD byte format into a CoMID representation for use in appraisal.

This profile extends the `flags-map` to represent the guest policy and host platform info that are unique to AMD SEV-SNP.
This profile extends the `$version-scheme` enumeration to account for the `FAMILY_ID` and `IMAGE_ID` fields of the ID block.
The profile extends the `$crypto-key-type-choice` to represent the SHA-384 digest of a key in AMD format from the [SEV-SNP.API].

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

[VCEK]:
  Versioned Chip Endorsement Key.
  A key for signing the SEV-SNP Attestation Report.
  The key is derived from a unique device secret as well as the security patch levels of relevant host components.

[VLEK]:
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

The instance identifier can be argued as any of `REPORT_ID`, `REPORT_ID_MA` when non-zero, `CHIP_ID` (for VCEK), or `CSP_ID` (for VLEK).
Given that `REPORT_ID` and `REPORT_ID_MA` are more ephemeral measured values and not the instance of the AMD-SP as the attesting environment, they are relegated to measurements.
Any endorsement of VM instances specific to either the `REPORT_ID` or `REPORT_ID_MA` values SHOULD use a conditional endorsement triple.

The different notions of identity induce different classes of attestation to identify target environments.
The different classes of attestation are

*  By chip: The `environment-map / instance` is `560(CHIP_ID)`.
*  By CSP: The `environment-map / instance is `560(CSP_ID)`.

The `class-id` for the Target Environment measured by the AMD-SP is a tagged UUID that corresponds to the attestation class:

*  By chip: d05e6d1b-9f46-4ae2-a610-ce3e6ee7e153
*  By CSP: 89a7a1f0-e704-4faa-acbd-81c86df8a961

TODO: AMD to assign OIDs for the above classes, e.g., `#6.111(1.3.6.1.4.1.3704.2.1)` through `#6.111(1.3.6.1.4.1.3704.2.4)`.
The rest of the `class-map` MUST remain empty, since `class` is compared for deterministic CBOR binary encoding equality.

The `group` is free for a CoRIM issuer to assign.

If the `SIGNING_KEY` bit of the attestation report is 1 indicating VLEK use, then the `class-id` MUST NOT be by chip.

~~~ cbor-diag
{::include cddl/examples/environment.diag}
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

* `0x0`: The GUEST measurements for `FAMILY_ID`, `IMAGE_ID`, `GUEST_SVN`, `MEASUREMENT`, `POLICY` flags.
* `0x1`: The MINIMUM_ABI guest measurement for `POLICY`'s lower 16 bits `MAJOR_ABI` and `MINOR_ABI`.
* `0x2`: The VMPL of the report.
* `0x3`: The REPORT_ID.
* `0x4`: The REPORT_ID_MA.
* `0x5`: The ID_KEY_DIGEST.
* `0x6`: The AUTHOR_KEY_DIGEST.
* `0x7`: The REPORTED_TCB host measurement.
* `0x8`: The HOST measurements for `CURRENT_BUILD`, `CURRENT_MAJOR`, `CURRENT_MINOR`, `CURRENT_TCB`, `HOSTDATA`, and `PLATFORM_INFO` flags in `&(flags: 3)`.
* `0x9`: The COMMITTED host measurements for `COMMITTED_BUILD`, `CURRENT_MAJOR`, `CURRENT_MINOR`, and `COMMITTED_TCB`.
* `0xa`: The LAUNCH_TCB host measurement.

The `REPORT_DATA` is meant for protocol use and not reference measurements.
The `MAJOR_ABI`, `MINOR_ABI` of the `POLICY` are not entirely redundant with Verifier policy evaluation against the `HOST`'s `&(version: 0)` since the policy may relevant to key derivations.

### AMD SEV-SNP Evidence Translation

The `ATTESTATION_REPORT` Evidence is converted into a CoRIM internal representation ECT for the `ae` relation using the rules in this section.

#### `environment`

If `SIGNING_KEY` is 0

*  The `environment-map / class / class-id` field SHALL be set to `37(h'd05e6d1b9f464ae2a610ce3e6ee7e153')`.
*  The `environment-map / instance ` field
   - MAY be `560(CHIP_ID)` only if `MASK_CHIP_KEY` is 0, or
   - MAY be `560(hwid)` where `hwid` is from the VCEK certificate extension value of `1.3.6.1.4.1.3704.1.4`.

If `SIGNING_KEY` is 1

*  The `environment-map / class / class-id` field SHALL be set to `37(h'89a7a1f0e7044faaacbd81c86df8a961')`.
*  The `environment-map / instance ` field SHALL be `560(CSP_ID)`.

#### `element-list`

Different fields of the attestation report correspond to different `element-id`s that correspond to their `mkey` value of a CoMID.

The translation makes use of the following metafunctions:

*  The function `is-set(x, b)` represents whether the bit at position `b` is set in the number `x`.
*  The function `hex(bstr)` represents the hexadecimal string encoding of a byte string.
*  The function `dec(b)` represents a byte in its decimal string rendering.
*  The function `leuint(bstr)` represents the translation of a byte string into a CBOR `uint` using a little-endian interpretation.

Juxtaposition of expressions with string literals is interpreted with string concatenation.

Note: A value of `0` is not treated the same as unset given the semantics for matching `flags-map`.

* `/ element-id: / 0`, the guest data `element-claims`
  +  The `&(version: 0)` codepoint MAY be unset if the report does not contain ID block data, otherwise the `&(version: 0)` codepoint SHALL be set to `/ version-map / { / version: / 0: vstr / version-scheme: / 1: -1 }` with version string `vstr` constructed as `hex(FAMILY_ID) '/' hex(IMAGE_ID)`.
  +  The `&(svn: 1)` codepoint MAY be unset if the report does not contain ID block data, otherwise the `&(svn: 1)` codepoint SHALL be set to `552(leuint(GUEST_SVN))`.
  +  The `&(digests: 2)` codepoint SHALL be set to `[ / digest / [ / alg: / 7, / val: / MEASUREMENT ] ]`. The algorithm assignment is from {{-named-info}} for SHA384.
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
* `/ element-id: / 1`, guest policy minimum firmware `element-claims`
  + The `&(version: 0)` SHALL be set to `/ version-map / { / version: /: dec(POLICY[15:8]) '.' dec(POLICY[7:0]) '.0' , / version-scheme: / 16384 }`.
* `/ element-id: 2 /` the report privilege level `element-claims`
  + The `&(raw-value: 5)` codepoint SHALL be set to `VMPL` as a `uint`.
* `/ element-id: 3 /` the per-launch `REPORT_ID` `element-claims`
  + The `&(raw-value: 5)` codepoint SHALL be set to `560(REPORT_ID)`.
* `/ element-id: 4 /` the migration agent–assigned `REPORT_ID_MA` `element-claims`
  + The `&(raw-value: 5)` codepoint SHALL be set to `560(REPORT_ID_MA)` if nonzero.
* `/ element-id: 5 /` the ID block–signing key digest `ID_KEY_DIGEST` `element-claims`
  + The `&(raw-value: 5)` codepoint SHALL be set to `560(ID_KEY_DIGEST)` if nonzero.
* `/ element-id: 6 /` the ID block–signing key's certifying key digest `AUTHOR_KEY_DIGEST` `element-claims`
  + The `&(raw-value: 5)` codepoint SHALL be set to `560(AUTHOR_KEY_DIGEST)` if nonzero.
* `/ element-id: 7 /` the REPORTED_TCB `element-claims`
  + The `&(svn: 1)` codepoint SHALL be set to `552(leuint(REPORTED_TCB))`.
* `/ element-id: 8 /` the current host info `element-claims`
  + The `&(version: 0)` codepoint SHALL be set to `/ version-map / { / version: 0 / vstr / version-scheme: / 1: 16384 }` with version string `vstr` constructed as `dec(CURRENT_MAJOR) '.' dec(CURRENT_MINOR) '.' dec(CURRENT_BUILD)`.
  + The `&(flags: 3) / flags-map / sevsnphost-smt-enabled` codepoint SHALL be set to `is-set(PLATFORM_INFO, 0)`
  + The `&(flags: 3) / flags-map / sevsnphost-tsme-enabled` codepoint SHALL be set to `is-set(PLATFORM_INFO, 1)`
  + The `&(flags: 3) / flags-map / sevsnphost-ecc-mem-reported-enabled` codepoint SHALL be set to `is-set(PLATFORM_INFO, 2)`
  + The `&(flags: 3) / flags-map / sevsnphost-rapl-disabled` codepoint SHALL be set to `is-set(PLATFORM_INFO, 3)`
  + The `&(flags: 3) / flags-map / sevsnphost-ciphertext-hiding-enabled` codepoint SHALL be set to `is-set(PLATFORM_INFO, 4)`
  + Any further non-reserved bit position `b` of `PLATFORM_INFO` will be set at `flags-map` codepoint `-1-b`.
  + The `&(raw-value: 5)` codepoint SHALL be set to `560(HOSTDATA)` and MAY be omitted if all zeros.
* `/ element-id: 9 /` the committed host info `element-claims`
  + The `&(svn: 1)` codepoint SHALL be set to `552(leuint(COMMITTED_TCB))`.
* `/ element-id: 4 /` the TCB at launch `element-claims`
  + The `&(svn: 1)` codepoint SHALL be set to `552(leuint(LAUNCH_TCB))`.
* `/ element-id: 10 /` the guest policy's minimum SEV-SNP ABI version that launch compares against `CURRENT_MAJOR` and `CURRENT_MINOR`.
  + The `&(version: 0)` codepoint SHALL be set to `/ version-map / { / version: / 0: vstr / version-scheme: / 1: 16384 }` with version string `vstr` constructed as `dec(MAJOR_ABI) '.' dec(MINOR_ABI) '.0'`.

#### `authority`

The `authority` SHALL be set to an array of the `tagged-pkix-asn1der-cert-type` forms of the VEK certificate for the `ATTESTATION_REPORT` signing key, the intermediate key, and the AMD root key for the product line.

The Verifier MAY add additional encodings of these keys.

#### `cmtype`

The `cmtype` SHALL be `evidence: 2`.


#### `profile`

The `profile` SHALL be set to this profile's identifier, `32("http://amd.com/please-permalink-me")`

#### Optional: ID block as reference value

If an ID block is provided at VM launch, it is authenticated by an ID key.
The ID block authentication is checked by the AMD-SP firmware.
The firmware will only launch the VM if the authenticated policy matches.
The firmware indicates that the authentication passed by populating fields of the attestation report to bind the evidence to the authentication key(s) `ID_KEY_DIGEST` and/or `AUTHOR_KEY_DIGEST`.
The ID block authentication as reference value SHALL NOT be retained by the Verifier to apply to another appraisal session.
The reference value qualification is meant to be considered valid only for the duration of the appraisal session.

The Verifier MAY allocate an `rv` for an addition ECT to represent the authentication at `SNP_LAUNCH_FINISH`.

* The `environment` SHALL be equal to the `environment` of the evidence ECT.
* The `element-list` SHALL contain two `element-map` entries
  + The first `element-map` SHALL set `element-id` to 0 and the `element-claims` to a copy of the evidence claims for `element-id: 0`.
  + The second `element-map` SHALL set `element-id` to 1 and the `element-claims` to a copy of the evidence claims for `element-id: 1`.
* The `authority` SHALL be an array containing `32780(ID_KEY_DIGEST)` and `32780(AUTHOR_KEY_DIGEST)` if nonzero. The Verifier MAY add more encodings of the same keys.
* The `cmtype` SHALL be set to `reference-values: 0`
* The `profile` SHALL be set to this profile's identifier, `32("http://amd.com/please-permalink-me")`.

# IANA Considerations

## New CBOR Tags

IANA is requested to allocate the following tags in the "CBOR Tags" registry {{!IANA.cbor-tags}}.

| Tag   | Data Item | Semantics                              | Reference |
| ---   | --------- | ---------                              | --------- |
| 32780 | `bytes`   | A digest of an AMD public key format.  | {{&SELF}} |
{: #cbor-tags title="Added CBOR tags"}

## New media types

### `application/vnd.amd.sev.snp.attestation-report`

An octet-stream that is expected to be interpreted as an AMD SEV-SNP ATTESTATION_REPORT.

### `application/vnd.amd.ghcb.guid-table`

An octet-stream that follows the [GHCB]'s GUID table ABI, which is the same as the [SVSM] service manifest ABI, recounted here.
A GUID table is a header followed by an octet-stream body.
The header is a sequence of entries described in {{guid_table_entry}} terminated by an all zero entry.
After the all zero entry are the bytes that the header entries index into.

| Type | Name | Description |
| ---- | ---- |
| `UUID` | GUID | An [RFC4122] byte format UUID |
| `LE_UINT32` | Offset | A little-endian offset into the the GUID table |
| `LE_UINT32` | Length | A little-endian byte length of the span |
{: #guid_table_entry title="guid_table_entry type description"}

Note that an offset is from the start of the octet-stream, and not from the start of the octets following the zero entry of the header.
A header entry is valid if its Offset+Length is less than or equal to the size of the entire GUID table.

--- back

# CoRIM Extensions CDDL {#sec-corim-cddl}

~~~ cddl
{::include cddl/corim-autogen.cddl}
~~~
