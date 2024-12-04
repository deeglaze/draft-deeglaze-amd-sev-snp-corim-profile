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
  I-D.ietf-rats-concise-ta-stores: ta-store

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

The `CSP_ID` is only evident from the `VLEK` certificate, which uses the ASN.1 IA5String encoding.
For the `tagged-bytes` representation, however, the `CSP_ID` SHALL be the UTF-8 encoding of the text string.

The `class-id` for the Target Environment measured by the AMD-SP is a tagged UUID that corresponds to the attestation class:

*  By chip: d05e6d1b-9f46-4ae2-a610-ce3e6ee7e153
*  By CSP: 89a7a1f0-e704-4faa-acbd-81c86df8a961

TODO: AMD to assign OIDs for the above classes, e.g., `#6.111(1.3.6.1.4.1.3704.2.1)` and `#6.111(1.3.6.1.4.1.3704.2.2)`.

The `&(model: 2)` field of the `class-map` is specific to the product name of the chip as determined by the family/model (not stepping) value.
The text for `model` MUST be the `product_name` specified in the [VCEK] specification, e.g., "Milan" or "Genoa".

The rest of the `class-map` MUST remain empty, since `class` is compared for deterministic CBOR binary encoding equality.

The `group` is free for a CoRIM issuer to assign.

If the `SIGNING_KEY` bit of the attestation report is 1 indicating VLEK use, then the `class-id` MUST NOT be by chip.

~~~ cbor-diag
{::include cddl/examples/environment.diag}
~~~

### AMD SEV-SNP Attestation Report measurements

The fields of an attestation report are named by `mkey` numbers that map to appropriate `measurement-values-map` values.
This profile defines no new `measurement-values-map` extensions for the `$$measurement-values-map-extensions` socket.
Flag-like values are delegated to the `raw-value` and `raw-value-mask` measurement values.

#### AMD SEV-SNP measurements

The measurements in an ATTESTATION_REPORT are each assigned an `mkey` value and the field value is translated to an appropriate `measurement-values-map` entry.
The convention for `mkey` value assignment is to sequential ordering when there are no reserved bits.
The `mkey` following a reserved bit is the bit position in the report of the start of the value.
The `R[lo:hi]` notation will reference the attestation report byte slice from offset `lo` inclusive to `hi` exclusive.
The `leuint(slice)` function translates a byte string in little endian to its `uint` representation.

**mkey 0**: VERSION.
Expressed as `&(raw-value: 4): tagged-leuint32`.

**mkey 1**: GUEST_SVN.
Expressed as `&(raw-value: 4): tagged-bytes4`.

**mkey 2**: POLICY.
Expressed as `&(raw-value: 4): tagged-bytes8` with optional `&(raw-value-mask: 5): tagged-bytes8` to restrict the reference value to the masked bits.

**mkey 3**: FAMILY_ID.
Expressed as `&(raw-value: 4): tagged-bytes16`.

**mkey 4**: IMAGE_ID.
Expressed as `&(raw-value: 4): tagged-bytes16`.

**mkey 5**: VMPL.
Expressed as `&(raw-value: 4): tagged-leuint32`.

**SIGNATURE_ALGO skipped**: `R[0x034:0x38]` only needed for signature verification.

**mkey 6**: CURRENT_TCB.
Expressed as `&(svn: 1): svn-type .and svn64-type`

**mkey 7**: PLATFORM_INFO.
Expressed as `&(raw-value: 4): tagged-bytes8` with optional `&(raw-value-mask: 5): tagged-bytes8` to restrict the reference value to the masked bits.

**AUTHOR_KEY_EN skipped**: AUTHOR_KEY_DIGEST will be present in evidence if and only if this bit is 1.
**MASK_CHIP_KEY skipped**: CHIP_ID will be present in evidence if and only if this bit is 0.
**SIGNING_KEY skipped**: The environment's class is determined by the attestation key kind.

**mkey 640**: REPORT_DATA.
Expressed as `&(raw-value: 4): tagged-bytes64`.

**mkey 641**: MEASUREMENT.
Expressed as `&(digests: 2): [[7, bytes48]]`.

**mkey 642: HOST_DATA.
Expressed as `&(digests: 2): [[7, bytes48]]`.

**mkey 643**: ID_KEY_DIGEST.
Expressed as `&(digests: 2): [[7, bytes48]]`.

**mkey 644**: AUTHOR_KEY_DIGEST.
Expressed as `&(digests: 2): [[7, bytes48]]`.

**mkey 645**: REPORT_ID.
Expressed as `&(raw-value: 4): tagged-bytes32`

**mkey 646**: REPORT_ID_MA.
Expressed as `&(raw-value: 4): tagged-bytes32`

**mkey 647**: REPORTED_TCB
Expressed as `&(svn: 1): svn64-type`.

**mkey 648**: CPUID_FAM_ID.
Expressed as `&(raw-value: 4): tagged-byte`.

**mkey 649**: CPUID_MOD_ID.
Expressed as `&(raw-value: 4): tagged-byte`.

**mkey 650**: CPUID_STEP.
Expressed as `&(raw-value: 4): tagged-byte`.

**mkey 3328**: CHIP_ID.
Expressed as `&(raw-value: 4): tagged-bytes64`.

**mkey 3329**: COMMITTED_TCB:
Expressed as `&(svn: 1): svn64-type`.

**mkey 3330**: CurrentVersion.
Expressed as `&(version: 0): semver-version-map`

**mkey 3936**: CommittedVersion.
Expressed as `&(version: 0): semver-version-map`

**mkey 3968**: LAUNCH_TCB.
Expressed as `&(svn: 1): svn64-type`.

### AMD SEV-SNP Evidence Translation to `reference-triple-record`

The `ATTESTATION_REPORT` Evidence is converted into a CoRIM internal representation given the canonical translation from a `reference-triple-record` as evidence conceptual message.

#### `environment`

If `SIGNING_KEY` is 0

*  The `environment-map / class / class-id` field SHALL be set to `37(h'd05e6d1b9f464ae2a610ce3e6ee7e153')`.
*  The `environment-map / instance ` field
   - MAY be `560(CHIP_ID)` only if `MASK_CHIP_KEY` is 0, or
   - MAY be `560(hwid)` where `hwid` is from the VCEK certificate extension value of `1.3.6.1.4.1.3704.1.4`.

If `SIGNING_KEY` is 1

*  The `environment-map / class / class-id` field SHALL be set to `37(h'89a7a1f0e7044faaacbd81c86df8a961')`.
*  The `environment-map / instance ` field SHALL be `560(CSP_ID)`.

#### `measurement-map`
The translation makes use of the following metafunctions:

*  The function `dec(b)` represents a byte in its decimal string rendering.

Juxtaposition of expressions with string literals is interpreted with string concatenation.

Note: A value of `0` is not treated the same as unset given the semantics for matching `flags-map`.

**no mkey**:

The `&(flags: 3)` codepoint SHALL be set to a `flags-map` with the following construction:

*  `is-confidentiality-protected` MAY be set to true.
*  `is-integrity-protected` MAY be set to true.
*  `is-replay-protected` MAY be set to true.
*  `is-debug` SHALL be set to the truth value of bit 19 of `POLICY`.

**mkey 0**: VERSION.
The codepoint `&(raw-value: 4)` SHALL be set to `560(R[0x000:0x004])`.

**mkey 1**: GUEST_SVN.
4 bytes.
The codepoint `&(raw-value: 4)` SHALL be set to `560(R[0x004:0x008])`.

**mkey 2**: POLICY.
8 bytes.
The codepoint `&(raw-value: 4)` SHALL be set to `560:(R[0x008:0x010])` with optional `&(raw-value-mask: 5): tagged-bytes` to restrict the reference value to the masked bits.

**mkey 3**: FAMILY_ID.
16 bytes.
The codepoint `&(raw-value: 4)` SHALL be set to `560:(R[0x010:0x020])`.

**mkey 4**: IMAGE_ID.
16 bytes.
The codepoint `&(raw-value: 4)` SHALL be set to `560:(R[0x020:0x030])`.

**mkey 5**: VMPL.
4 bytes.
The codepoint `&(raw-value: 4)` SHALL be set to `560:(R[0x030:0x034])`.

**SIGNATURE_ALGO skipped**: `R[0x034:0x38]` only needed for signature verification.

**mkey 6**: CURRENT_TCB.
The codepoint `&(svn: 1)` SHALL be set to `552(current_tcb)` where `current_tcb` is `R[0x038:0x40]` translated to `uint` from its little-endian representation.

**mkey 7**: PLATFORM_INFO.
The codepoint `&(raw-value: 4)` SHALL be set to `560(R[0x040:0x048])`.

**AUTHOR_KEY_EN skipped**: AUTHOR_KEY_DIGEST will be present in evidence if and only if this bit is 1.
**MASK_CHIP_KEY skipped**: CHIP_ID will be present in evidence if and only if this bit is 0.
**SIGNING_KEY skipped**: The environment's class is determined by the attestation key kind.

**mkey 640**: REPORT_DATA.
The codepoint `&(raw-value: 4)` SHALL be set to `560(R[0x050:0x090])`.

**mkey 641**: MEASUREMENT.
The codepoint `&(digests: 2)` SHALL be set to `[[7, R[0x090:0x0C0]]]`.

**mkey 642: HOST_DATA.
The codepoint `&(digests: 2)` SHALL be set to `[[7, R[0x0C0:0x0E0]]]`.

**mkey 643**: ID_KEY_DIGEST.
The codepoint `&(digests: 2): [[7, R[0x0E0:0x110]]]` SHALL be set.

**mkey 644**: AUTHOR_KEY_DIGEST.
The codepoint `&(digests: 2)` SHALL be set to `[[7, R[0x110:0x140]]]` only if AUTHOR_KEY_EN (`R[0x048] & 1`) is 1.

**mkey 645**: REPORT_ID.
The codepoint `&(raw-value: 4)` SHALL be set to `560(R[0x140:0x160])`

**mkey 646**: REPORT_ID_MA.
The codepoint `&(raw-value: 4)` SHALL be set to `560(R[0x160:0x180])` only if non-zero.

**mkey 647**: REPORTED_TCB
The codepoint `&(svn: 1)` SHALL be set to `552(reported_tcb)` where `reported_tcb` is `REPORTED_TCB` (`R[0x180:0x188]`) translated to `uint` from its little-endian representation.

**mkey 648**: CPUID_FAM_ID.
The codepoint `&(raw-value: 4)` SHALL be set to `560(R[0x188:0x189])` only if VERSION (little endian `R[0x000:0x004]`) is at least 3.

**mkey 649**: CPUID_MOD_ID.
The codepoint `&(raw-value: 4)` SHALL be set to `560(R[0x189:0x18A])` only if VERSION (little endian `R[0x000:0x004]`) is at least 3.

**mkey 650**: CPUID_STEP.
The codepoint `&(raw-value: 4)` SHALL be set to `560(R[0x18A:0x18B])` only if VERSION (little endian `R[0x000:0x004]`)is at least 3.

**mkey 3328**: CHIP_ID.
The codepoint `&(raw-value: 4)` SHALL be set to `560(R[0x1A0:0x1E0])` only if MASK_CHIP_KEY (`R[0x048] & 2`) is 0.

**mkey 3329**: COMMITTED_TCB.
The codepoint `&(svn: 1)` SHALL be set to `552(committed_tcb)` where `committed_tcb` is `REPORTED_TCB` (`R[0x1E0:0x1E8]`) translated to `uint` from its little-endian representation.

**mkey 3330**: CurrentVersion.
The `&(version: 0)` codepoint SHALL be set to

~~~ cbor-diag
/ version-map / {
  / version: 0 / vstr
  / version-scheme: / 1: 16384
}
~~~
The version string `vstr` is constructed as `dec(R[0x1EA]) '.' dec(R[0x1E9]) '.' dec(R[0x1E8])`.

**mkey 3936**: CommittedVersion.
The `&(version: 0)` codepoint SHALL be set to

~~~ cbor-diag
/ version-map / {
  / version: 0 / vstr
  / version-scheme: / 1: 16384
}
~~~
The version string `vstr` is constructed as `dec(R[0x1EE]) '.' dec(R[0x1ED]) '.' dec(R[0x1EC])`.

**mkey 3968**: LAUNCH_TCB.
The codepoint `&(svn: 1)` SHALL be set to `552(launch_tcb)` where `launch_tcb` is `LAUNCH_TCB` (`R[0x1F0:0x1F8]`) translated to `uint` from its little-endian representation.

#### `cmtype`

The `cmtype` SHALL be `evidence: 2`.


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

#### VEK Certificate `attest-key-triple-record`

Each VEK Certificate from AMD's Key Distribution Service (KDS) contains extensions that associate the key to its target environment.
There is no condition on `REPORTED_TCB` to form this association, since the keys will only ever verify evidence that corresponds the the `REPORTED_TCB` they were derived from.

To allow for certificates to be reissued, the keys associated to an environment use only the `SubjectPublicKeyInfo`.
For consistent comparison, the `$crypto-key-type-choice` encoding is a #6.557-tagged SHA256 digest (`alg: 1`) of the ASN.1 encoding as defined in [RFC5280].
Let `vcek_pk` represent the tagged key identifier of the `VCEK` public key.

A [VCEK] certificate may be interpreted with `hwid` as the octet-string value from X.509 extension 1.3.6.1.4.1.3704.1.4 as

~~~ cbor-diag
{::include cddl/examples/vcek-triple.diag}
~~~

Note: KDS may not encode the `hwid` with the octet string type tag `0x04` and length information (definite, short, 64) `0x40` of the x.509 extension value.
If the length is 64 bytes, then that is the exact `hwid`.

Let `vlek_pk` be the encoded VLEK public key.
A [VLEK] certificate SHALL be associated with an environment with a "by CSP" `class-id` and instance value as a `tagged-bytes` of the UTF-8 encoded `csp_id` string from X.509 extension 1.3.6.1.4.1.3704.1.5 as

~~~ cbor-diag
{::include cddl/examples/vlek-triple.diag}
~~~

It is expected that the Verifier will require or admit a trust anchor that associates the AMD root key and AMD SEV key certificates for a `product_name` (from KDS endpoint `vcek/v1/{product_name}/cert_chain` or `vlek/v1/{product_name}/cert_chain`) with the appropriate environment class in order to validate the attestation key certificates.
If using a CoTS {{-ta-store}} tag for trust anchor specification, an appropriate `purpose` for verifying a VEK cerificate is `"eat"`.

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

### `application/vnd.amd.sev-snp.attestation-report`

A byte string that is expected to be interpreted as an AMD SEV-SNP ATTESTATION_REPORT.

### `application/vnd.amd.ghcb.guid-table`

An byte string that follows the {{GHCB}}'s GUID table ABI, which is the same as the [SVSM] service manifest ABI, recounted here.
A GUID table is a header followed by an byte string body.
The header is a sequence of entries described in {{guid_table_entry}} terminated by an all zero entry.
After the all zero entry are the bytes that the header entries index into.

| Type | Name | Description |
| ---- | ---- |
| `UUID` | GUID | An [RFC4122] byte format UUID |
| `LE_UINT32` | Offset | An offset into the the GUID table |
| `LE_UINT32` | Length | A byte length of the span |
{: #guid_table_entry title="guid_table_entry type description"}

An `LE_UINT32` is a 4 byte byte string that represents a nonnegative integer in little-endian order.

Note that an offset is from the start of the byte string, and not from the start of the octets following the zero entry of the header.
A header entry is valid if its Offset+Length is less than or equal to the size of the entire GUID table.

## New CoAP Content-Formats entries

The content types application/vnd.amd.sev-snp.attestation-report` and `application/vnd.amd.ghcb.guid-table` need Content-Formats IDs to be used in the EAT `measurements` claim.
Requesting 10572 and 10573 respectively.

--- back

# CoRIM Extensions CDDL {#sec-corim-cddl}

~~~ cddl
{::include cddl/corim-autogen.cddl}
~~~
