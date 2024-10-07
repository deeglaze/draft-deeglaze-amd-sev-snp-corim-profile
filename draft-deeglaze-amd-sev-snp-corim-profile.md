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
  RFC4122:
  RFC8174:
  RFC8610: cddl
  RFC9334: rats-arch
  I-D.ietf-rats-corim: rats-corim
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

This profile is meant for expressing reference values and endorsements of specific environments. It is not meant to encode complex policy decisions about the acceptability of measurements. The accepted claim set construction (ACS) this profile enables does lay a foundation for policy engines that enable further evaluation over complete ACS constructions.

This profile extends the `flags-map` to represent the guest policy and host platform info that are unique to AMD SEV-SNP.
The profile extends the `$crypto-key-type-choice` to represent the SHA-384 digest of a key in AMD format from Appendix: Digital Signatures of {{SEV-SNP.API}}.

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

{{VCEK}}:
  Versioned Chip Endorsement Key.
  A key for signing the SEV-SNP Attestation Report.
  The key is derived from a unique device secret as well as the security patch levels of relevant host components.

{{VLEK}}:
  Version Loaded Endorsement Key.
  An alternative SEV-SNP Attestation Report signing key that is derived from a secret shared between AMD and a Cloud Service Provider.
  The key is encrypted with a per-device per-version wrapping key that is then decrypted and stored by the AMD-SP.

VEK:
  Either a VCEK or VLEK.

## AMD SEV-SNP CoRIM Profile

AMD SEV-SNP launch endorsements are carried in one or more CoMIDs inside a CoRIM.

The profile attribute in the CoRIM MUST be present and MUST have a single entry set to the URI http://amd.com/please-permalink-me as shown in {{figure-profile}}.

~~~ cbor-diag
{::include cddl/examples/profile.diag}
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
*  By CSP: The `environment-map / instance` is `560(CSP_ID)`.

The `class-id` for the Target Environment measured by the AMD-SP is a tagged UUID that corresponds to the attestation class:

*  By chip: d05e6d1b-9f46-4ae2-a610-ce3e6ee7e153
*  By CSP: 89a7a1f0-e704-4faa-acbd-81c86df8a961

TODO: AMD to assign OIDs for the above classes, e.g., `#6.111(1.3.6.1.4.1.3704.2.1)` and `#6.111(1.3.6.1.4.1.3704.2.2)`.
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

#### AMD SEV-SNP `flags-map` extensions {#sec-flags-ext}

The `POLICY` field and the `PLATFORM_INFO` field of the attestation report contain flags distinguished from the base CoRIM CDDL.

The `POLICY` boolean flags are added as extensions to `$$flags-map-extension`, starting from codepoint -1.

~~~ cddl
{::include cddl/sevsnpvm-guest-policy-flags-ext.cddl}
~~~

The `sevsnpvm-policy-` flag extensions correspond to the ATTESTATION_REPORT `POLICY` bit positions with the following correspondence:

*  `sevsnpvm-policy-smt-allowed` refers to bit 16 of `POLICY`.
*  `sevsnpvm-policy-migration-agent-allowed` refers to bit 18 of `POLICY`.
*  `sevsnpvm-policy-debug-allowed` refers to bit 19 of `POLICY`.
*  `sevsnpvm-policy-single-socket-only` refers to bit 20 of `POLICY`.
*  `sevsnpvm-policy-cxl-allowed` refers to bit 21 of `POLICY`.
*  `sevsnpvm-policy-mem-aes-256-xts-required` refers to bit 22 of `POLICY`.
*  `sevsnpvm-policy-rapl-must-be-disabled` refers to bit 23 of `POLICY`.
*  `sevsnpvm-policy-ciphertext-hiding-must-be-enabled` refers to bit 24 of `POLICY`.
*  Bit position `b` greater than `24` of `POLICY` corresponds to extension `16-b`.

There are 47 available bits for selection when the mandatory 1 in position 17 and the ABI Major.Minor values are excluded from the 64-bit `POLICY`.
The `PLATFORM_INFO` bits are host configuration that are added as extensions to `$$flags-map-extension` starting at `-49`.

~~~ cddl
{::include cddl/sevsnphost-platform-info-flags-ext.cddl}
~~~

The `sevsnphost-` flag extensions correspond to ATTESTATION_REPORT `PLATFORM_INFO` bit positions with the following correspondence:

*  `sevsnphost-smt-enabled` refers to bit 0 of `PLATFORM_INFO`.
*  `sevsnphost-tsme-enabled` refers to bit 1 of `PLATFORM_INFO`.
*  `sevsnphost-ecc-mem-reported-enabled` refers to bit 2 of `PLATFORM_INFO`.
*  `sevsnphost-rapl-disabled` refers to bit 3 of `PLATFORM_INFO`.
*  `sevsnphost-ciphertext-hiding-enabled` refers to bit 4 of `PLATFORM_INFO`.
*  Bit position `b` greater than `4` of `PLATFORM_INFO` corresponds to extension `-49-b`.

The `sevsnpvm-policy-debug-allowed` flag is redundant with `flags-map / is-debug`, so either representation is valid.
The entirety of the value space is reserved for AMD revisions to the SEV-SNP firmware and corresponding ATTESTATION_REPORT API.

#### AMD SEV-SNP measurements

The measurements in an ATTESTATION_REPORT are grouped into 10 `mkey`s that can refer to one or more measured values.

The `REPORT_DATA` is meant for protocol use and not reference measurements.

**mkey 0**: primary guest measurements

The `mval` `measurement-values-map` may contain values for `GUEST_SVN`, `MEASUREMENT`, `POLICY` flags, `FAMILY_ID` and/or `IMAGE_ID`.

*  The `GUEST_SVN` 32-bit unsigned integer may be given a reference value as an `svn-type` with a `tagged-svn` or `tagged-min-svn` encoding around a `uint32` in an `&(svn: 1): svn-type` entry.
*  The `MEASUREMENT` 384-bit digest may be referenced with a `&(digest: 2): [[7, MEASUREMENT]]` entry.
*  The `POLICY` flags may be referenced with a `&(flags: 3): flags-map` entry following the correspondence defined in {{sec-flags-ext}}
*  The `IMAGE_ID` may be referenced with a `&(version: 0): / version-map / { &(version: 0): hex(IMAGE_ID) }`, where `hex(IMAGE_ID)` is the 128-bit identifier translated to a hexadecimal string.
*  The `FAMILY_ID` may be referenced as `&(raw-value: 4): 560(FAMILY_ID)`.

**mkey 1**: The minimum ABI guest policy

The ATTESTATION_REPORT `POLICY`'s lower 16 bits `MAJOR_ABI` and `MINOR_ABI` is expressed as version with semantic versioning scheme that has patch version `0`.

~~~ cbor-diag
{::include cddl/examples/minabi.diag}
~~~

The `MAJOR_ABI`, `MINOR_ABI` of the `POLICY` are not entirely redundant with Verifier policy evaluation against host's (mkey 8) `&(version: 0)` since the policy may relevant to key derivations.

**mkey 2** The VMPL of the report.

The `VMPL` is expressed as a raw value that makes use of the extended `$raw-value-type-choice` to use a `uint`.
To refer to `VMPL` 2, say

~~~ cbor-diag
{::include cddl/examples/vmpl.diag}
~~~

**mkey 3**: The REPORT_ID.

The `REPORT_ID` is expressed as a `&(raw-value: 4): tagged-bytes`.

**mkey 4**: The REPORT_ID_MA.

The `REPORT_ID_MA` is expressed as a `&(raw-value: 4): tagged-bytes`.

**mkey 5**: The ID_KEY_DIGEST.

The `ID_KEY_DIGEST` is expressed as a `&(raw-value: 4): tagged-bytes`.

**mkey 6**: The AUTHOR_KEY_DIGEST.

The `AUTHOR_KEY_DIGEST` is expressed as a `&(raw-value: 4): tagged-bytes`.

**mkey 7**: The REPORTED_TCB host measurement.

The `REPORTED_TCB` is interpreted as a little-endian 64-bit unsigned integer and expressed as an `&(svn: 1): svn-type .and svn64-type`, where

~~~ cddl
{::include cddl/svn64-type.cddl}
~~~

**mkey 8**: The current host measurements

The `CURRENT_MAJOR`, `CURRENT_MINOR`, and `CURRENT_BUILD` fields are expressed as a version with semantic version scheme.
The version text is the three numbers in decimal form, separated by `'.'` (U+002E), in major, minor, build order.

The `HOSTDATA` field is expressed as a raw value. The `PLATFORM_INFO` are expressed with a `flags` measurement with the specified flag extensions. For example,

~~~ cbor-diag
{::include cddl/examples/host.diag}
~~~

* `0x9`: The COMMITTED host measurements for `COMMITTED_BUILD`, `CURRENT_MAJOR`, `CURRENT_MINOR`, and `COMMITTED_TCB`.

The `COMMITTED_MAJOR`, `COMMITTED_MINOR`, and `COMMITTED_BUILD` fields are expressed as a version with semantic version scheme.
The version text is the three numbers in decimal form, separated by `'.'` (U+002E), in major, minor, build order.

The `COMMITTED_TCB` is interpreted as a little-endian 64-bit unsigned integer and expressed as an `&(svn: 1): svn-type .and svn64-type`.
For example, suppose the committed TCB has microcode SVN 209, SNP firmware version 22, TEE version 0, and bootloader version 3

~~~ cbor-diag
{::include cddl/examples/committed.diag}
~~~

* `0xa`: The LAUNCH_TCB host measurement.

The `LAUNCH_TCB` is interpreted as a little-endian 64-bit unsigned integer and expressed as an `&(svn: 1): svn-type .and svn64-type`.

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

*  The function `hex(bstr)` represents the hexadecimal string encoding of a byte string.
*  The function `dec(b)` represents a byte in its decimal string rendering.

Juxtaposition of expressions with string literals is interpreted with string concatenation.

Note: A value of `0` is not treated the same as unset given the semantics for matching `flags-map`.

**element-id: 0**, the guest data `element-claims`

The `&(version: 0)` codepoint MAY be unset if the report does not contain ID block data, otherwise the `&(version: 0)` codepoint SHALL be set to

~~~ cbor-diag
/ version-map / {
  / version: / 0: hex(IMAGE_ID)
}
~~~

The `&(svn: 1)` codepoint MAY be unset if the report does not contain ID block data, otherwise the `&(svn: 1)` codepoint SHALL be set to `552(leuint(GUEST_SVN))`.

The `&(digests: 2)` codepoint SHALL be set to `[[7, MEASUREMENT]]`.
The algorithm assignment is from {{-named-info}} for SHA384.

The `&(flags: 3)` codepoint SHALL be set to a `flags-map` with the following construction:

*  `is-confidentiality-protected` MAY be set to true.
*  `is-integrity-protected` MAY be set to true.
*  `is-replay-protected` MAY be set to true.
*  `is-debug` SHALL be set to the truth value of bit 19 of `POLICY`.
*  The extensions for `POLICY` are assigned their truth values following the correspondence in {{sec-flags-ext}}.

The `$(raw-value: 4)` codepoint MAY be unset if the report does not contain ID block data, otherwise the `&(raw-value: 4)` codepoint SHALL be set to `560(FAMILY_ID)`.

**element-id: 1**, guest policy minimum firmware `element-claims`

The `&(version: 0)` SHALL be set to

~~~ cbor-diag
/ version-map / {
  / version: /: dec(POLICY[15:8]) '.' dec(POLICY[7:0]) '.0'
  / version-scheme: / 16384
}
~~~

**element-id: 2**, the report privilege level `element-claims`

The `&(raw-value: 5)` codepoint SHALL be set to `VMPL` as a `uint`.

**element-id: 3**, the per-launch `REPORT_ID` `element-claims`

The `&(raw-value: 5)` codepoint SHALL be set to `560(REPORT_ID)`.

**element-id: 4**, the migration agent–assigned `REPORT_ID_MA` `element-claims`

The `&(raw-value: 5)` codepoint SHALL be set to `560(REPORT_ID_MA)` if nonzero.

**element-id: 5**, the ID block–signing key digest `ID_KEY_DIGEST` `element-claims`

The `&(raw-value: 5)` codepoint SHALL be set to `560(ID_KEY_DIGEST)` if nonzero.

**element-id: 6**, the ID block–signing key's certifying key digest `AUTHOR_KEY_DIGEST` `element-claims`

The `&(raw-value: 5)` codepoint SHALL be set to `560(AUTHOR_KEY_DIGEST)` if nonzero.

**element-id: 7**, the REPORTED_TCB `element-claims`

The `&(svn: 1)` codepoint SHALL be set to `552(reported_tcb)` where `reported_tcb` is `REPORTED_TCB` translated to `uint` from its little-endian representation.

**element-id: 8**, the current host info `element-claims`

The `&(version: 0)` codepoint SHALL be set to

~~~ cbor-diag
/ version-map / {
  / version: 0 / vstr
  / version-scheme: / 1: 16384
}
~~~
The version string `vstr` is constructed as `dec(CURRENT_MAJOR) '.' dec(CURRENT_MINOR) '.' dec(CURRENT_BUILD)`.

The `&(flags: 3) / flags-map` extensions for `PLATFORM_INFO` SHALL be assign their truth values following the correspondence is {{sec-flags-ext}}.

The `&(raw-value: 5)` codepoint SHALL be set to `560(HOSTDATA)` and MAY be omitted if all zeros.

**element-id: 9**, the committed host info `element-claims`

The `&(version: 0)` codepoint SHALL be set to

~~~ cbor-diag
/ version-map / {
  / version: 0 / vstr
  / version-scheme: / 1: 16384
}
~~~
The version string `vstr` is constructed as `dec(COMMITTED_MAJOR) '.' dec(COMMITTED_MINOR) '.' dec(COMMITTED_BUILD)`.

The `&(svn: 1)` codepoint SHALL be set to `552(commited_tcb)` where `committed_tcb` is `COMMITTED_TCB` translated to a `uint` from its little-endian representation.

**element-id: 10**, the TCB at launch `element-claims`

The `&(svn: 1)` codepoint SHALL be set to `552(launch_tcb)` where `launch_tcb` is `LAUNCH_TCB` translated to a `uint` from its little-endian representation.

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

# TCG considerations

The Trusted Computing Group has standardized the PCClient Platform Firmware Profile to specify expected TPM event log processing.
Since AMD SEV-SNP launch measurements are of virtual firmware, they can supplement the `EV_POST_CODE2` event measured into PCR0 for the `EV_EFI_PLATFORM_FIRMWARE_BLOB2` since the bits of the firmware are more specific than embedded firmware version strings.

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

An octet-stream that follows the {{GHCB}}'s GUID table ABI, which is the same as the [SVSM] service manifest ABI, recounted here.
A GUID table is a header followed by an octet-stream body.
The header is a sequence of entries described in {{guid_table_entry}} terminated by an all zero entry.
After the all zero entry are the bytes that the header entries index into.

| Type | Name | Description |
| ---- | ---- |
| `UUID` | GUID | An [RFC4122] byte format UUID |
| `LE_UINT32` | Offset | An offset into the the GUID table |
| `LE_UINT32` | Length | A byte length of the span |
{: #guid_table_entry title="guid_table_entry type description"}

An `LE_UINT32` is a 4 byte octet-stream that represents a nonnegative integer in little-endian order.

Note that an offset is from the start of the octet-stream, and not from the start of the octets following the zero entry of the header.
A header entry is valid if its Offset+Length is less than or equal to the size of the entire GUID table.

--- back

# CoRIM Extensions CDDL {#sec-corim-cddl}

~~~ cddl
{::include cddl/corim-autogen.cddl}
~~~
