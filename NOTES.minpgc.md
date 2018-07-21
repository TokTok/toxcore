# Proposal
We add one new invite packet type:

Rejoin packet

| Length | Contents                        |
|:-------|:--------------------------------|
| `1`    | `uint8_t` (0x60)                |
| `1`    | `uint8_t` (0x04)                |
| `33`   | Group chat identifier           |


When a peer times out from a group (no ping received for 60s), we don't delete 
it, but just flag the peer as _frozen_. Disconnected peers are disregarded for 
all purposes except those discussed below - in particular no packets are sent 
to them except as described below, they are omitted from the peer lists sent 
to the client or in a Peer Response packet, and they are not considered when 
determining closest peers for establishing direct connections.

Below we talk about _thawing_ frozen peers. This means we remove the
'frozen' flag, and send a Name group message. (We can hold off on sending
this message until the next tox\_iterate, and only send one message if many
peers thaw at once).

If we receive a group message originating from a frozen peer, we thaw the
peer and then process the message as usual.

If we receive a group message originating from an unknown peer, we drop the
message but send a Peer Query packet back to the peer who directly sent us the
message. (This is current behaviour; it's mentioned here because it's important
and not currently mentioned in the spec.)

If we receive a New Peer message for a peer with public key that of an
frozen peer, we thaw the peer and update its dht key.

If we receive a Rejoin packet from a peer we thaw the peer if it is frozen,
update its dht key, and proceed as for an Invite Response, except that we do
not give the peer a new peer number. In particular, we send out a New Peer
message and add a temporary groupchat connection for the peer.

Whenever we make a new friend connection, we check if the public key is that 
of any frozen peer. If so, we behave as if we were accepting an invite from
that peer, but with the new packet: namely, we send it a Rejoin packet, add a
temporary groupchat connection for it, and send it a Peer Query packet.

We do the same with a peer when we are setting it as frozen if we have a
friend connection to it.

The temporary groupchat connections established in sending and handling Rejoin
packets are not immediately operational (because group numbers are not known);
rather, an Online packet is sent when we handle a Rejoin packet.

When a connection is set as online as a result of an Online packet, we ping
the group.

When we receive a Title Response packet, we set the title if it is currently
empty or if all peers became frozen since we last set the title.

# Discussion
## Overview
The intention is to recover seemlessly from splits in the group, the most 
common form of which is a single peer losing their internet connection.

If two peers in different connected components have a friend connection (due 
to actually being friends, or due to a group connection surviving), by the 
above process each will add the other's component to their peer list, and so 
then through ping packets being forwarded the two components will remerge. The 
Peer Query and List packets sent on thawing a peer are sufficient in
most circumstances to ensure that any new peers which joined either component
during the split will be properly incorporated, and the handling of a message
from an unknown peer deals with the remaining exceptional circumstances. Peers
who leave the group during a split will not be deleted by all peers after the
merge, but they will be set as frozen due to ping timeouts, which is
sufficient.

## Titles
If we have a split into components each containing multiple peers, and the
title is changed in one component, then peers will continue to disagree on the
title after the split. Short of a complicated voting system, this seems the
only reasonable behaviour.

## Backwards compatibility
In the simplest and most important case that one peer disconnects from the
rest of the group, as long as the above protocol is being followed by both
that disconnected peer and at least one other member of the group who is also
a Tox friend of the disconnected peer, then the peer will successfully
reintegrate into the group even if the rest of the group is using older
versions of toxcore, and even if the group has added and/or lost members
during the disconnection.

## Implementation notes
Although I've described the logic in terms of an 'frozen' flag, it might 
actually make more sense in the implementation to have a separate list for 
frozen peers.

# Saving
Saving could be implemented by simply saving all live groups with their group
numbers and full peer info for all peers. On reload, all peers would be set as
frozen.

The client would need to support this by understanding that these groups exist
on start-up (e.g. starting windows for them), and by not automatically killing
groups on closing the client.
