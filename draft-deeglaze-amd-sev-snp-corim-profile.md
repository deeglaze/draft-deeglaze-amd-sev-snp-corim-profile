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
This profile extends the `$version-scheme` enumeration to account for the `FAMILY_ID` and `IMAGE_ID` fields of the IDBLOCK.

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

# IANA Considerations

## New CBOR Tags

IANA is requested to allocate the following tags in the "CBOR Tags" registry {{!IANA.cbor-tags}}.
The choice of the CoRIM-earmarked value is intentional.

| Tag   | Data Item | Semantics                                                                             | Reference |
| ---   | --------- | ---------                                                                             | --------- |
| 563   | `map`     | Keys are always int, values are opaque bytes, see {{sec-id-tag}}                      | {{&SELF}} |
| 32780 | `bytes`   | A digest of an AMD public key format that compares with other keys {{sec-key-digest}} | {{&SELF}} |
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
