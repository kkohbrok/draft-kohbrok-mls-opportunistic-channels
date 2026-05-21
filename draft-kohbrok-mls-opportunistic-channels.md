---
title: "Opportunistic MLS Channels"
abbrev: "OMC"
category: info

docname: draft-kohbrok-mls-opportunistic-channels-latest
submissiontype: IETF
number:
date:
consensus: true
v: 3
area: "Security"
workgroup: "Messaging Layer Security"
keyword:
 - messaging
venue:
  group: "Messaging Layer Security"
  type: "Working Group"
  mail: "mls@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/mls/"
  github: "kkohbrok/draft-kohbrok-mls-opportunistic-channels"
  latest: "https://kkohbrok.github.io/draft-kohbrok-mls-opportunistic-channels/"

author:
 -
    fullname: Konrad Kohbrok
    organization: Phoenix R&D
    email: konrad@ratchet.ing
 -
    fullname: Raphael Robert
    organization: Phoenix R&D
    email: ietf@raphaelrobert.com

normative:
  RFC9420:
  I-D.ietf-mls-extensions:
  I-D.ietf-mls-targeted-messages:

informative:

...

--- abstract

This document defines two extensions to the Messaging Layer Security (MLS)
protocol.  First, it defines an MLS WireFormat that follows the encrypted MLS
PrivateMessage format, but omits the sender signature and relies on symmetric
authentication by group secrets.  Second, it defines Opportunistic Channel
Groups, a two-member MLS group variant that is bootstrapped from an existing
MLS group using an MLS targeted message and evolves only by injecting PSKs from
MLS groups shared by both members.


--- middle

# Introduction

MLS {{RFC9420}} provides authenticated group key agreement, encrypted
application messages, and group evolution with forward secrecy and
post-compromise security.  Some applications need a light-weight encrypted
channel between two members who already share at least one MLS group.  Creating
a normal two-member MLS group for every such channel carries the full cost of an
MLS ratchet tree, which can be restrictive, especially when using post-quantum
ciphersuites.

This document has two parts.

The first part defines `mls_unsigned_private_message`, an MLS WireFormat that
can be used in any MLS group that has negotiated support for the format.  It is
the same encrypted framing as MLS PrivateMessage, except that the
FramedContentAuthData signature is not transmitted and is not verified.  The
format therefore authenticates that the sender is a member of the group, but it
does not authenticate the sender identity indicated by the sender leaf index.

The second part defines Opportunistic Channel Groups (OCGs).  An OCG is an MLS
group with exactly two members, no ratchet tree, and a GroupContext that marks
the group as an OCG using an MLS application component.  OCGs are bootstrapped
through MLS targeted messages {{I-D.ietf-mls-targeted-messages}} sent in an
existing MLS group.  OCGs advance epochs only by committing PreSharedKey
proposals that inject resumption PSKs from MLS groups shared by both members.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

This document uses the terminology and presentation language from {{RFC9420}}.

The notation `0` is used as in {{RFC9420}}, namely an all-zero byte string of
length `KDF.Nh` for the cipher suite in use.  When this document sets a
`tree_hash` value to zero, the value is the all-zero byte string of length
`KDF.Nh`.

# Unsigned Private Messages

This section defines a new MLS WireFormat that is independent of OCGs.  Any MLS
group can use this WireFormat if all members support it.  When the MLS
extensions negotiation mechanism is available, the sender advertises support
with the `supported_wire_formats` LeafNode extension and the group requires
support with the `required_wire_formats` GroupContext extension defined in
{{I-D.ietf-mls-extensions}}.

All RFC 9420 validation rules for PrivateMessages to apply, except for
validation of the omitted FramedContentAuthData signature as described below.

The new WireFormat name is `mls_unsigned_private_message`.  Its content is an
`UnsignedPrivateMessage`.

~~~
case mls_unsigned_private_message:
    UnsignedPrivateMessage unsigned_private_message;
~~~

## Format

`UnsignedPrivateMessage` has the same outer fields as `PrivateMessage` in
{{RFC9420}}.

~~~
struct {
    opaque group_id<V>;
    uint64 epoch;
    ContentType content_type;
    opaque authenticated_data<V>;
    opaque encrypted_sender_data<V>;
    opaque ciphertext<V>;
} UnsignedPrivateMessage;
~~~

The content encrypted in `ciphertext` is an `UnsignedPrivateMessageContent`.
This structure carries the same content alternatives and padding rules as
`PrivateMessageContent`, but omits the `signature` field from
`FramedContentAuthData`.  Commits still carry a confirmation tag.

~~~
struct {
    select (UnsignedPrivateMessage.content_type) {
        case application:
          opaque application_data<V>;

        case proposal:
          Proposal proposal;

        case commit:
          Commit commit;
    };

    select (UnsignedPrivateMessage.content_type) {
        case commit:
            MAC confirmation_tag;
        case application:
        case proposal:
            struct{};
    };

    opaque padding[length_of_padding];
} UnsignedPrivateMessageContent;
~~~

The `encrypted_sender_data` field is computed as in Section 6.3.2 of
{{RFC9420}}.  The `SenderData` structure, sender data AAD, ciphertext sample,
key derivation, nonce derivation, and sender data validation rules are
unchanged.

The content encryption uses the same AEAD keys, nonces, AAD, reuse guard, and
padding rules as Section 6.3.1 of {{RFC9420}}, with
`UnsignedPrivateMessageContent` in place of `PrivateMessageContent`.

TODO: Decide whether we want a dedicated ratchet for unsigned private messages?

## Decoding

After decrypting an `UnsignedPrivateMessage`, the receiver reconstructs the
corresponding `FramedContent` from the outer message fields, decrypted sender
data, and decrypted content, following the same construction used for
`PrivateMessage` in {{RFC9420}}.

For compatibility with RFC 9420 algorithms that consume an
`AuthenticatedContent` value, an unsigned private message is represented as an
`AuthenticatedContent` with:

* `wire_format` set to `mls_unsigned_private_message`.

* `content` set to the reconstructed `FramedContent`.

* `auth.signature` set to the zero-length octet string.

* `auth.confirmation_tag` set to the confirmation tag carried in the message,
  if the content type is `commit`.

Receivers MUST NOT verify a signature for an
`mls_unsigned_private_message`.  Receivers MUST verify the confirmation tag for
a Commit as described in {{RFC9420}}.

## Transcript Hashes and Proposal References

RFC 9420 computes transcript hashes and Proposal references over
`AuthenticatedContent` objects.  Because this WireFormat does not carry a
signature, this document defines the canonical `AuthenticatedContent`
representation above.  Senders and receivers MUST use this representation in
all RFC 9420 algorithms that consume an `AuthenticatedContent` value.

For a Commit carried in `mls_unsigned_private_message`,
`ConfirmedTranscriptHashInput.signature` is the zero-length octet string.  The
other fields of `ConfirmedTranscriptHashInput` and
`InterimTranscriptHashInput` are computed as in {{RFC9420}}.

For a Proposal carried in `mls_unsigned_private_message`, `MakeProposalRef` uses
the encoded `AuthenticatedContent` representation with `auth.signature` set to
the zero-length octet string.  This rule is necessary because, without it, two
implementations could decrypt the same unsigned Proposal but hash different byte
strings when producing a Proposal reference.

## Sender Authentication

`mls_unsigned_private_message` authenticates that the message was created by a
party with access to the relevant MLS epoch secrets.  It does not authenticate
which group member created the message.  Any group member that can derive the
message protection keys for an epoch can construct a valid message that claims
any non-blank member sender index in that epoch.

Applications MUST NOT use this WireFormat when cryptographic sender
authentication is required.  Applications that use this WireFormat MUST treat
the sender index as a claimed sender index authenticated only by group
membership.

# Opportunistic Channel Groups

An Opportunistic Channel Group is an MLS group variant with exactly two
members.  OCGs use the MLS key schedule, transcript hashes, message protection,
GroupContext, and PSK processing defined in {{RFC9420}}, except where this
document explicitly changes those rules.

An OCG has no ratchet tree.  Instead, the OCG has two virtual member positions
with leaf indices 0 and 1.  The member that creates the OCG has OCG leaf index
0.  The member that receives the bootstrap targeted message has OCG leaf index
1.  These indices are used in the `SenderData.leaf_index` field of
`mls_unsigned_private_message`.

OCG messages MUST be encoded as `mls_unsigned_private_message`.  A receiver
MUST reject an OCG message with any other WireFormat.

## OCG Marker Component

An OCG is identified by the presence of an `opportunistic_channel` application
component in the `app_data_dictionary` GroupContext extension defined in
{{I-D.ietf-mls-extensions}}.

~~~
struct {
} OpportunisticChannel;
~~~

The OCG ComponentID is `0x0008`.  The `opportunistic_channel` component MUST
appear only in GroupContext objects.  Its presence marks the group as an OCG.

## OCG Group State

An OCG member maintains the following state:

* A GroupContext.

* The MLS epoch secrets derived as part of the MLS key schedule.

* A secret tree with exactly two leaves, indexed 0 and 1.

* The transcript hashes defined in {{RFC9420}}.

* A capability source for each OCG member, as defined in {{capabilities}}.

An OCG does not maintain a RatchetTree.  The `tree_hash` field of the
GroupContext MUST be set to `0` in every epoch.  A receiver MUST reject an OCG
GroupContext whose `tree_hash` is not the all-zero byte string of length
`KDF.Nh`.

The `commit_secret` input to the MLS key schedule MUST be `0` for every OCG
epoch transition.

OCGs do not support adding, removing, or updating members.  An OCG always has
exactly two members.

## Bootstrapping

An OCG is bootstrapped from an existing MLS group, called the bootstrap source
group.  The bootstrap source group MUST contain both OCG members in the epoch
used for bootstrapping.

The OCG creator sends an MLS targeted message to the other OCG member in the
bootstrap source group.  The targeted message `application_data` field MUST
contain an `OCGBootstrap` value.

~~~
struct {
    GroupContext group_context;
    Extension extensions<V>;
    MAC confirmation_tag;
} UnsignedGroupInfo;

struct {
    opaque joiner_secret<V>;
    UnsignedGroupInfo group_info;
} OCGBootstrap;
~~~

`joiner_secret` MUST be a fresh random byte string of length `KDF.Nh` for the
OCG cipher suite.  The OCG cipher suite MUST be the cipher suite of the
bootstrap source group.

TODO: Maybe generate `joiner_secret` from the target message HPKE context.

The `UnsignedGroupInfo` structure is the OCG analogue of the `GroupInfo`
structure in {{RFC9420}}, without the `signer` and `signature` fields.  The
integrity and sender authentication of this object are provided by the targeted
message in the bootstrap source group.

The OCG GroupContext in the bootstrap message MUST have:

* `version` set to `mls10`.

* `cipher_suite` set to the cipher suite of the bootstrap source group.

* `epoch` set to 0.

* `tree_hash` set to `0`.

* `confirmed_transcript_hash` set to the zero-length octet string.

* `extensions` containing the `opportunistic_channel` component.

* `extensions` containing a `required_wire_formats` extension that requires
  `mls_unsigned_private_message`.

The `UnsignedGroupInfo.extensions` field MUST NOT contain a `ratchet_tree`
extension.  OCG bootstrap does not use any RatchetTre, or GroupInfo signature
validation steps from {{RFC9420}}.

The creator derives the OCG epoch 0 secrets from `joiner_secret` using the epoch
secret derivation that Welcome processing uses after GroupInfo decryption in
{{RFC9420}}.  The PSK list is empty, so `psk_secret` is `0`.  The
`joiner_secret` value from `OCGBootstrap` is used directly as the epoch 0
`joiner_secret`. The two-leaf OCG secret tree is derived from the resulting
`encryption_secret` as in {{RFC9420}}, with leaf 0 corresponding to the
bootstrap sender and leaf 1 corresponding to the bootstrap recipient.  The
creator computes the epoch 0 confirmation tag over the zero-length confirmed
transcript hash and includes it in `UnsignedGroupInfo.confirmation_tag`.

The recipient processes the targeted message according to
{{I-D.ietf-mls-targeted-messages}}.  The recipient then validates the
`OCGBootstrap` value, verifies that the OCG `group_id` is not already in use by
one of the recipient's MLS groups, derives the epoch 0 secrets from
`joiner_secret`, and verifies `UnsignedGroupInfo.confirmation_tag`.  If any
validation step fails, the recipient MUST reject the bootstrap message and MUST
NOT create the OCG state.

## Proposals and Commits

The only proposal type allowed in an OCG is `psk`.  A receiver MUST reject an
OCG Proposal containing any other proposal type.  After resolving all proposal
references in an OCG Commit, a receiver MUST reject the Commit if any resolved
proposal is not a PreSharedKey proposal.

TODO: Maybe allow other proposal types, Application content proposals may be
good to allow.

An OCG Commit MUST contain at least one PreSharedKey proposal.  A receiver MUST
reject an OCG Commit whose `proposals` vector is empty.

An OCG Commit MUST NOT contain an UpdatePath.  A receiver MUST reject an OCG
Commit whose `path` field is populated.

Every PreSharedKey proposal in an OCG Commit MUST identify a resumption PSK
whose `usage` is `application`.  The `psk_group_id` and `psk_epoch` fields
identify the source group and source group epoch.  The referenced source group
epoch MUST contain both OCG members, and both OCG members MUST be able to
authenticate the source group state according to their application policy.

When creating or processing an OCG Commit, the proposal list is applied as in
{{RFC9420}}, with all tree operations omitted.  The new GroupContext is derived
from the old GroupContext by incrementing the epoch, setting `tree_hash` to
`0`, preserving the GroupContext extensions, and updating the transcript hash
as defined for `mls_unsigned_private_message`.

The `psk_secret` is derived from the committed PreSharedKey proposals as in
{{RFC9420}}.  The `commit_secret` is `0`.  The new epoch secrets are then
derived with the MLS key schedule using the new GroupContext, `psk_secret`, and
`commit_secret`.

## Capabilities {#capabilities}

OCGs have no RatchetTree and therefore do not have OCG-local LeafNodes from
which capabilities and capability negotiation extensions can be read.  Instead,
each OCG member has a capability source.  A capability source identifies a
source group, a source group epoch, the GroupContext for that source group
epoch, and the LeafNode that represents the OCG member in that source group
epoch.

The inherited capability state for an OCG member consists of the following
values from the capability source:

* The `capabilities` field of the source LeafNode.

* The `supported_wire_formats` extension in the source LeafNode, if present.

* The `required_wire_formats` extension in the source GroupContext, if present.
  A WireFormat required by the source GroupContext is treated as supported by
  every member represented in that source group epoch.

* The `app_data_dictionary` extension in the source LeafNode, if present, with
  the components that have support semantics in {{I-D.ietf-mls-extensions}}.
  This includes `safe_aad`, `app_components`, and `content_media_types`.

* The `app_data_dictionary` extension in the source GroupContext, if present,
  with the same support-semantic components.  Values required by the source
  GroupContext are treated as supported by every member represented in that
  source group epoch.

From OCG creation until the first OCG Commit, the capability source for both
members is the LeafNode for that member in the bootstrap source group and epoch.

After an OCG Commit is accepted, the capability source for the Commit sender is
the LeafNode for that member in the source group and epoch identified by the
first PreSharedKey proposal in the Commit's resolved proposal list.  The
capability source for the other member is unchanged.

When an OCG member evaluates whether the peer supports an extension, proposal
type, credential type, cipher suite, WireFormat, component, or media type, it
MUST use the peer's current inherited capability state.

An OCG member MUST ignore unknown values in inherited capability negotiation
extensions according to {{I-D.ietf-mls-extensions}}.

# Security Considerations

The `mls_unsigned_private_message` WireFormat intentionally removes MLS sender
signatures.  It provides confidentiality and group membership authentication
for message contents, but it does not provide sender authentication.  The
sender leaf index is a claim made by a party with access to the MLS epoch
secrets.

In any group using `mls_unsigned_private_message`, a malicious member can forge
messages that appear to come from another member.

This property has a key-compromise impersonation consequence in two-party
groups.  If Alice's OCG state is compromised, an attacker can use Alice's copy
of the epoch secrets to send Alice a valid OCG message that claims Bob's sender
index.  Alice can verify only that the message was produced with OCG epoch
secrets.  Alice cannot verify that Bob produced it.

The same property creates a sender-ratchet denial of service risk.  An attacker
that has compromised a member's OCG state can create messages under the other
member's sender index and advance the receiver's view of that sender's message
ratchet.  This can cause later honest messages from that sender to be rejected
as reused or out of order.  Applications using OCGs need a recovery strategy,
such as committing a fresh shared PSK from a source group or recreating the OCG.

OCGs do not use UpdatePaths.  As a result, OCG Commits do not provide the
post-compromise security properties that RFC 9420 obtains from fresh path
secrets in a RatchetTree.  Injecting PSKs from MLS groups shared by both OCG
members can provide a weaker form of post-compromise security for OCG epoch
secrets.  This weaker property holds only if the source group epoch provides a
resumption PSK unknown to the attacker and the attacker cannot prevent both
members from accepting the OCG Commit.

The OCG bootstrap relies on the security properties of MLS targeted messages.
The unsigned GroupInfo in the bootstrap message is authenticated by the
targeted message from the bootstrap source group.  A recipient MUST complete
targeted message validation before processing the embedded `OCGBootstrap`
value.

# IANA Considerations

This document requests the following registration in the "MLS Wire Formats"
registry:

| Value | Name | Recommended | Reference |
| 0x0007 | mls_unsigned_private_message | N | RFCXXXX |

This document requests the following registration in the "MLS Component Types"
registry defined by {{I-D.ietf-mls-extensions}}:

| Value | Name | Where | Recommended | Reference |
| 0x0008 | opportunistic_channel | GC | N | RFCXXXX |


--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
