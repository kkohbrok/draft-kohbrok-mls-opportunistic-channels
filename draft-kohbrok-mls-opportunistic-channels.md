---
title: "Opportunistic Channels"
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

...

--- abstract

This document defines Opportunistic Channels: a way for two members of a
Messaging Layer Security (MLS) group to efficiently create and operate an
end-to-end encrypted 1-to-1 channel. In contrast to a full MLS group, the
channel participants can't independently update their key material. Instead,
participants opportunistically inject key material exported from other groups.
As such, opportunistic channels are more efficient than full MLS groups, but
achieve lower security guarantees. Their use-case is the transmission of
lower-security messages such as message delivery receipts.

To keep messaging in opportunistic channels efficient, this document also
defines MLS WireFormats that are equivalent to MLS' PublicMessage and
PrivateMessage, but omit signatures. These WireFormats are otherwise independent
of opportunistic channels and can be used in regular MLS groups.

--- middle

# Introduction

MLS {{!RFC9420}} provides authenticated group key agreement, encrypted
application messages, and group evolution with forward secrecy and
post-compromise security.  Some applications need a light-weight encrypted
channel between two members who already share at least one MLS group, for
example to transmit read or delivery receipts.

Creating a normal two-member MLS group for every such channel carries the full
cost of an MLS ratchet tree, which can be restrictive, especially when using
post-quantum cipher suites.

This document has two parts.

The first part defines Opportunistic Channels (OCs).  An OC is an MLS group with
exactly two members, no ratchet tree, and a GroupContext that marks the group as
an OC using an MLS application component.  OCs are bootstrapped through MLS
targeted messages {{!I-D.ietf-mls-targeted-messages}} sent in an existing MLS
group.  OCs achieve post-compromise security by committing PreSharedKey
proposals that inject resumption PSKs from MLS groups shared by both members.

The second part defines unsigned variants of the MLS PublicMessage and
PrivateMessage WireFormats. These WireFormats are not specific to OCs and can
be used by any MLS group whose members support them.  They
use the same framing as their signed MLS counterparts, except that the
signature is not transmitted and is not verified.  The formats therefore
authenticate that the sender is a member of the group, but they do not
authenticate the sender identity indicated by the sender leaf index.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

This document uses the terminology and presentation language from {{!RFC9420}}.

# Opportunistic Channels

An Opportunistic Channel is an MLS group variant with exactly two
members.  OCs use the MLS key schedule, transcript hashes, message protection,
GroupContext, and PSK processing defined in {{!RFC9420}}, except where this
document explicitly changes those rules.

An OC has no ratchet tree.  Instead, the OC has two virtual member positions
with leaf indices 0 and 1.  The member that creates the OC has OC leaf index 0.
The member that receives the bootstrap targeted message
({{I-D.ietf-mls-targeted-messages}}) has OC leaf index 1.

## OC Marker Component

An OC is identified by the presence of an `opportunistic_channel` application
component in the `app_data_dictionary` GroupContext extension defined in
{{!I-D.ietf-mls-extensions}}.

~~~ tls
struct {
} OpportunisticChannel;
~~~

The OC ComponentID is `0x0008` (suggested; see IANA Considerations).  The
`opportunistic_channel` component MUST appear only in GroupContext objects.

## OC State {#oc-state}

An OC member maintains the following state:

- A GroupContext.
- The MLS epoch secrets derived as part of the MLS key schedule.
- A secret tree with exactly two leaves, indexed 0 and 1.
- The transcript hashes defined in {{!RFC9420}}.
- A capability source for each OC member, as defined in {{capabilities}}.

An OC does not maintain a ratchet tree.  The `tree_hash` field of the
GroupContext MUST be set to the zero-length octet string in every epoch.  A
receiver MUST reject an OC GroupContext whose `tree_hash` is not the
zero-length octet string.

OCs do not support adding, removing, or updating members.

## Bootstrapping

An OC is bootstrapped from an existing MLS group, called the bootstrap source
group.  The bootstrap source group MUST contain both OC members in the epoch
used for bootstrapping.

The OC creator sends an MLS targeted message to the other OC member in the
bootstrap source group.  The targeted message `application_data` field MUST
contain an `OCBootstrap` value.

How a receiver recognizes that a targeted message payload contains an
`OCBootstrap` is up to the application.  Applications that use targeted
messages for more than one purpose MAY wrap targeted message payloads in a
container format of their choice that distinguishes the individual payload
types, for example the media-type-based `ApplicationFraming` format defined in
{{Section 6.2.4 of I-D.ietf-mls-extensions}}.

~~~ tls
struct {
    GroupContext group_context;
    Extension extensions<V>;
    MAC confirmation_tag;
} UnsignedGroupInfo;

struct {
    opaque joiner_secret<V>;
    UnsignedGroupInfo group_info;
} OCBootstrap;
~~~

`joiner_secret` MUST be a fresh random byte string of length `KDF.Nh` for the
OC cipher suite.  The OC cipher suite MUST be the cipher suite of the
bootstrap source group.

OPEN QUESTION: Maybe generate `joiner_secret` from the targeted message HPKE context.

The `UnsignedGroupInfo` structure is the OC analogue of the `GroupInfo`
structure in {{!RFC9420}}, without the `signer` and `signature` fields.  The
integrity and sender authentication of this object are provided by the targeted
message in the bootstrap source group.

The OC GroupContext in the bootstrap message MUST have:

- `group_id` set to a fresh value that is unique among the creator's MLS
  groups.
- `version` set to `mls10`.
- `cipher_suite` set to the cipher suite of the bootstrap source group.
- `epoch` set to 0.
- `tree_hash` set to the zero-length octet string.
- `confirmed_transcript_hash` set to the zero-length octet string.
- `extensions` containing the `opportunistic_channel` component and
  `required_wire_formats` extension

The creator MUST NOT include in the OC GroupContext a required WireFormat,
extension, proposal type, or component that is not supported by both OC
members according to their capability sources in the bootstrap source group
({{capabilities}}).

The `UnsignedGroupInfo.extensions` field MUST NOT contain a `ratchet_tree`
extension.  OC bootstrap does not use the ratchet tree or GroupInfo signature
validation steps from {{!RFC9420}}.

The creator derives the OC epoch 0 secrets by using the `joiner_secret` value
from `OCBootstrap` directly as the epoch 0 `joiner_secret` in the epoch secret
derivation that Welcome processing uses after GroupInfo decryption in
{{!RFC9420}}.  The PSK list is empty, so `psk_secret` is the all-zero vector of
length `KDF.Nh`, as specified in Section 8.4 of {{!RFC9420}}.  The two-leaf OC
secret tree is derived from the
resulting `encryption_secret` as in {{!RFC9420}}, with leaf 0 corresponding to
the bootstrap sender and leaf 1 corresponding to the bootstrap recipient.  The
creator computes the epoch 0 confirmation tag over the zero-length confirmed
transcript hash and includes it in `UnsignedGroupInfo.confirmation_tag`.

The recipient MUST complete targeted message validation according to
{{I-D.ietf-mls-targeted-messages}} before processing the embedded
`OCBootstrap` value.  The recipient then verifies that the `OCBootstrap` value
satisfies all requirements of this section, including that both OC members
support the capabilities required by the OC GroupContext according to their
capability sources ({{capabilities}}), verifies that the OC `group_id` is
not already in use by
one of the recipient's MLS groups, derives the epoch 0 secrets from
`joiner_secret`, and verifies `UnsignedGroupInfo.confirmation_tag`.  If any
validation step fails, the recipient MUST reject the bootstrap message and MUST
NOT create the OC state.

## Proposals and Commits

Proposals and Commits are created and processed as in {{!RFC9420}} with the
following exceptions:

- Proposals that require an update path or whose semantics affect or require
  the ratchet tree MUST NOT be used.  A recipient of an OC Commit that covers
  such a proposal, whether by value or by reference, MUST reject the Commit.
- An AppDataUpdate proposal ({{I-D.ietf-mls-extensions}}) in an OC MUST NOT
  add, modify, or remove the `opportunistic_channel` component.
- An OC Commit MUST NOT contain an `UpdatePath`.  As specified for Commits
  without a path in {{!RFC9420}}, the `commit_secret` input to the key
  schedule is therefore the all-zero vector of length `KDF.Nh`.
- `tree_hash` is set to the zero-length octet string when updating the
  GroupContext, as required by {{oc-state}}.

The restrictions around proposals are due to the lack of a ratchet tree in
OCs.  To achieve post-compromise security, group members should use
PreSharedKey proposals that inject a `usage=application` resumption PSK from
a group that contains both OC members; the referenced source group epoch MUST
contain both OC members.

OPEN QUESTION: Do we want to restrict proposals to an allow list instead of
the category-based rule above?  For example, the rule above permits ReInit
proposals, since they require neither an update path nor a ratchet tree, but
reinitialization as defined in {{!RFC9420}} relies on Welcome messages and
therefore cannot produce an OC.

## Message Processing

Members process OC messages according to the message processing rules of
{{!RFC9420}} and, where applicable, {{unsigned-messages}}, with the following
changes to validation steps that consult the ratchet tree:

- The `sender_type` of an OC message sender MUST be `member`, and the sender
  leaf index MUST be 0 or 1.  This rule replaces the RFC 9420 check that the
  sender leaf index identifies a non-blank leaf in the ratchet tree.
- For WireFormats that carry a signature, the receiver verifies the signature
  using the signature public key of the LeafNode in the sender's current
  capability source ({{capabilities}}) instead of a LeafNode in the OC's
  ratchet tree.

## Capabilities {#capabilities}

OCs have no ratchet tree and therefore do not have OC-local LeafNodes from
which capabilities and capability negotiation extensions can be read.  Instead,
each OC member has a capability source.  A capability source identifies a
source group, a source group epoch, the GroupContext for that source group
epoch, and the LeafNode that represents the OC member in that source group
epoch.  Determining which LeafNode represents an OC member in a source group
is the responsibility of the MLS Authentication Service (see {{!RFC9750}}).

The inherited capability state for an OC member consists of the following
values from the capability source:

- The `capabilities` field of the source LeafNode.
- The `supported_wire_formats` extension in the source LeafNode, if present.
- The `required_wire_formats` extension in the source GroupContext, if present.
  A WireFormat required by the source GroupContext is treated as supported by
  every member represented in that source group epoch.
- The `app_data_dictionary` extension in the source LeafNode, if present, with
  the components that have support semantics in {{I-D.ietf-mls-extensions}}.
  This includes `safe_aad`, `app_components`, and `content_media_types`.
- The `app_data_dictionary` extension in the source GroupContext, if present,
  with the same support-semantic components.  Values required by the source
  GroupContext are treated as supported by every member represented in that
  source group epoch.

From OC creation until the first OC Commit, the capability source for both
members is the LeafNode for that member in the bootstrap source group and epoch.

After an OC Commit that covers at least one resumption PreSharedKey proposal
is accepted, the capability source for the Commit sender is the LeafNode for
that member in the source group and epoch identified by the first such
proposal in the Commit's resolved proposal list.  The capability source for
the other member is unchanged.  An OC Commit that covers no resumption
PreSharedKey proposal does not change either capability source.

When an OC member evaluates whether the peer supports an extension, proposal
type, credential type, cipher suite, WireFormat, component, or media type, it
MUST use the peer's current inherited capability state.

An OC member MUST ignore unknown values in inherited capability negotiation
extensions according to {{I-D.ietf-mls-extensions}}.

# Unsigned Messages {#unsigned-messages}

This section defines two new MLS WireFormats that are independent of OCs:
`mls_unsigned_public_message` and `mls_unsigned_private_message`.  They are
equivalent to the `mls_public_message` and `mls_private_message` WireFormats
defined in {{!RFC9420}}, except that the `signature` field of
`FramedContentAuthData` is not transmitted and is not verified.

All other RFC 9420 validation rules for PublicMessages and PrivateMessages
apply.  Receivers MUST NOT verify a signature for these WireFormats and MUST
verify the confirmation tag for a Commit as described in {{!RFC9420}}.

To ensure transcript agreement, members MUST NOT send a Proposal or Commit using
one of these WireFormats unless the WireFormat is listed in the group's
`required_wire_formats` GroupContext extension defined in
{{I-D.ietf-mls-extensions}}.  A receiver MUST reject a Proposal or Commit that
does not satisfy this condition.

Application messages do not contribute to the shared group state, so members
MAY send them using one of these WireFormats under a weaker condition: every
member in the current epoch supports the WireFormat, as indicated by the
group's `required_wire_formats` extension or by the `supported_wire_formats`
LeafNode extension of every member.

~~~
case mls_unsigned_public_message:
    UnsignedPublicMessage unsigned_public_message;

case mls_unsigned_private_message:
    UnsignedPrivateMessage unsigned_private_message;
~~~

## Unsigned Public Messages

### Format

`UnsignedPublicMessage` has the same fields as `PublicMessage` in {{!RFC9420}},
except that the `signature` field of `FramedContentAuthData` is omitted and
the `membership_tag` is always present.

~~~
struct {
    FramedContent content;

    select (UnsignedPublicMessage.content.content_type) {
        case commit:
            MAC confirmation_tag;
        case application:
        case proposal:
            struct{};
    };

    MAC membership_tag;
} UnsignedPublicMessage;
~~~

The `sender_type` of an `UnsignedPublicMessage` sender MUST be `member`.
Senders with sender type `external`, `new_member_proposal`, or
`new_member_commit` are authenticated exclusively by their signature and
therefore cannot use this WireFormat.  A receiver MUST reject an
`UnsignedPublicMessage` with any other sender type.

As in {{!RFC9420}}, application messages MUST NOT be sent as
`UnsignedPublicMessage`: the `content_type` MUST be `proposal` or `commit`.

The `membership_tag` field is computed and verified as described in Section
6.2 of {{!RFC9420}}, with the `FramedContentAuthData` value in
`AuthenticatedContentTBM` taken from the canonical `AuthenticatedContent`
representation defined in {{authenticated-content}}, i.e., with the
`signature` field set to the zero-length octet string.

### Decoding

The receiver reconstructs the corresponding `AuthenticatedContent` from the
message fields as described in {{authenticated-content}}, with `wire_format`
set to `mls_unsigned_public_message`.

Receivers MUST verify the `membership_tag`.

## Unsigned Private Messages

### Format

`UnsignedPrivateMessage` has the same outer fields as `PrivateMessage` in
{{!RFC9420}}.

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
{{!RFC9420}}.  The `SenderData` structure, sender data AAD, ciphertext sample,
key derivation, nonce derivation, and sender data validation rules are
unchanged.

The content encryption uses the same AEAD keys, nonces, AAD, reuse guard, and
padding rules as Section 6.3.1 of {{!RFC9420}}, with
`UnsignedPrivateMessageContent` in place of `PrivateMessageContent`.

OPEN QUESTION: Do we want a dedicated ratchet for unsigned private messages?

### Decoding

After decrypting an `UnsignedPrivateMessage`, the receiver reconstructs the
corresponding `FramedContent` from the outer message fields, decrypted sender
data, and decrypted content, following the same construction used for
`PrivateMessage` in {{!RFC9420}}.  The corresponding `AuthenticatedContent` is
then constructed as described in {{authenticated-content}}, with `wire_format`
set to `mls_unsigned_private_message`.

## AuthenticatedContent Representation {#authenticated-content}

For compatibility with RFC 9420 algorithms that consume an
`AuthenticatedContent` value, an unsigned message is represented as an
`AuthenticatedContent` with:

- `wire_format` set to `mls_unsigned_public_message` or
  `mls_unsigned_private_message`, matching the WireFormat the message was
  framed in.
- `content` set to the message's `FramedContent` (for unsigned public
  messages) or the reconstructed `FramedContent` (for unsigned private
  messages).
- `auth.signature` set to the zero-length octet string.
- `auth.confirmation_tag` set to the confirmation tag carried in the message,
  if the content type is `commit`.

Senders and receivers MUST use this representation in all RFC 9420 algorithms
that consume an `AuthenticatedContent` value.

## Transcript Hashes and Proposal References

RFC 9420 computes transcript hashes and Proposal references over
`AuthenticatedContent` objects; the canonical representation defined in
{{authenticated-content}} applies as follows.

For a Commit carried in an unsigned message,
`ConfirmedTranscriptHashInput.signature` is the zero-length octet string.  The
other fields of `ConfirmedTranscriptHashInput` and
`InterimTranscriptHashInput` are computed as in {{!RFC9420}}.

For a Proposal carried in an unsigned message, `MakeProposalRef` uses the
encoded `AuthenticatedContent` representation with `auth.signature` set to
the zero-length octet string.  Without this rule, two implementations could
process the same unsigned Proposal but hash different byte strings when
producing a Proposal reference.

## Sender Authentication {#sender-authentication}

The WireFormats defined in this section authenticate that the message was
created by a party with access to the relevant MLS epoch secrets: the
`membership_key` in the case of `mls_unsigned_public_message`, and the message
protection keys derived from the `encryption_secret` in the case of
`mls_unsigned_private_message`.  They do not authenticate which group member
created the message.  Any group member that can derive those secrets for an
epoch can construct a valid message that claims any non-blank member sender
leaf index in that epoch.

Applications MUST NOT use these WireFormats when cryptographic sender
authentication is required.  Applications that use these WireFormats MUST
treat the sender leaf index as a claimed sender leaf index authenticated only
by group membership.

# Security Considerations

The `mls_unsigned_public_message` and `mls_unsigned_private_message`
WireFormats intentionally remove MLS sender signatures.  They provide group
membership authentication for message contents (and, in the case of
`mls_unsigned_private_message`, confidentiality), but, as described in
{{sender-authentication}}, they do not authenticate the sender: in any group
using these WireFormats, a malicious member can forge messages that appear to
come from another member.

This property has a key-compromise impersonation consequence in two-party
groups.  If Alice's OC state is compromised, an attacker can use Alice's copy
of the epoch secrets to send Alice a valid OC message that claims Bob's sender
index.  Alice can verify only that the message was produced with OC epoch
secrets.  Alice cannot verify that Bob produced it.

The same property creates a sender-ratchet denial of service risk.  An attacker
that has compromised a member's OC state can create messages under the other
member's sender leaf index and advance the receiver's view of that sender's message
ratchet.  This can cause later honest messages from that sender to be rejected
as reused or out of order.  Applications using OCs need a recovery strategy,
such as committing a fresh shared PSK from a source group or recreating the OC.

OCs do not use UpdatePaths.  As a result, OC Commits do not provide the
post-compromise security properties that RFC 9420 obtains from fresh path
secrets in a ratchet tree.  Injecting PSKs from MLS groups shared by both OC
members can provide a weaker form of post-compromise security for OC epoch
secrets.  This weaker property holds only if the source group epoch provides a
resumption PSK unknown to the attacker and the attacker cannot prevent both
members from accepting the OC Commit.

The OC bootstrap relies on the security properties of MLS targeted messages.
The unsigned GroupInfo in the bootstrap message is authenticated by the
targeted message from the bootstrap source group.

# IANA Considerations

This document requests the following registrations in the "MLS Wire Formats"
registry:

| Value | Name | Recommended | Reference |
| --- | --- | --- | --- |
| 0x0007 (suggested) | mls_unsigned_private_message | N | RFCXXXX |
| 0x0008 (suggested) | mls_unsigned_public_message | N | RFCXXXX |

This document requests the following registration in the "MLS Component Types"
registry defined by {{I-D.ietf-mls-extensions}}:

| Value | Name | Where | Recommended | Reference |
| --- | --- | --- | --- | --- |
| 0x0008 (suggested) | opportunistic_channel | GC | N | RFCXXXX |


--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
