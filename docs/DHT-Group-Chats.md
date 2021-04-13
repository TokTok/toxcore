# Group Chats
This document details the groupchat implementation, giving a high level overview of all the important features and aspects, as well as some important low level implementation details. This documentation reflects what is currently implemented at the time of writing; it is not speculative. For detailed API docs see the groupchats section of the tox.h header file.

## Index

- [Features](#Features)
- [Group roles](#Group_roles)
- [Group types](#Group_types)
  - [Public](#Public)
  - [Private](#Private)
- [Cryptography](#Cryptography)
  - [Permanent keypairs](#Permanent_keypairs)
  - [Session keypair](#Session_keypair)
  - [Group keypairs](#Group_keypairs)
- [Founders](#Founders)
  - [Shared state](#Shared_state)
- [Moderation](#Moderation)
  - [Kicks](#Kicks)
  - [Moderator list](#Moderator_list)
  - [Sanctions list](#Sanctions_list)
- [Topics](#Topics)
- [State syncing](#State_syncing)
- [DHT Announcements](#DHT_Announcements)

<a name="Features" />

## Features

* Plain and action messages (/me)
* Private messages
* Public groups (peers may join via a public key of group)
* Private groups (require a friend invite for join)
* Permanence (a group cannot 'die' as long as at least one peer retains their group credentials)
* Persistence across client restarts
* Ability to set peer limits
* Group roles (founder, moderators, users, observers)
* Moderation (kicking, silencing)
* Permanent group names (set on creation)
* Topics (may only be set by moderators and the founder)
* Password protection
* Self-repairing (auto-rejoin on disconnect, group split protection, state syncing)
* Identity separation from the Tox ID
* Ability to ignore peers
* Unique nicknames which can be set on a per-group basis
* Peer statuses (online, away, busy) which can be set on a per-group basis
* Sending group name in invites
* Ability to disconnect from group and join later with the same credentials

<a name="Group_roles" />

## Group roles

There are four distinct roles which are hierarchical in nature (higher roles have all the privileges of lower roles).

* **Founder** - The group's creator. May set all other peers roles to anything except founder. May also set the group password, toggle the privacy state, and set the peer limit.
* **Moderator** - Promoted by the founder. May kick non-moderators and set the user and observer roles for peers below this role. May also set the topic.
* **User** - Default non-founder role. May communicate with other peers normally.
* **Observer** - Demoted by moderators and the founder. May observe the group and ignore peers; may not communicate with other peers or with the group.

<a name="Group_types" />

## Group types

Groups can have two types: private and public. The type can be set on creation, and may also be toggled by the group founder at any point after creation. (_Note: password protection is independent of the group type_)

<a name="Public" />

### Public

Anyone may join the group using the Chat ID. If the group is public, information about peers inside the group, including their IP addresses and group public keys (but not their Tox ID's) is visible to anyone with access to a node storing their DHT announcement. See the [DHT Announcements](#DHT Announcements) section for details.

<a name="Private" />

### Private

The only way to join a private group is by having someone in your friend list send you an invite. If the group is private, no peer/group information (mentioned in the Public section) is present in the DHT; the DHT is not used for any purpose at all. If a public group is set to private, all DHT information related to the group will expire within a few minutes.

<a name="Cryptography" />

## Cryptography

Groupchats use the [NaCl/libsodium cryptography library](https://en.wikipedia.org/wiki/NaCl_(software)) for all cryptography related operations. All group communication is end-to-end encrypted. Message confidentiality, integrity, and repudability are guaranteed via [authenticated encryption](https://en.wikipedia.org/wiki/Authenticated_encryption), and [perfect forward secrecy](https://en.wikipedia.org/wiki/Forward_secrecy) is also provided.

One of the most important security improvements from the old groupchat implementation is the removal of a message-relay mechanism that uses a group-wide shared key. Instead, connections are 1-to-1 (a complete graph), meaning an outbound message is sent once per peer, and encrypted/decrypted using a session key unique to each pair of peers. This prevents MITM attacks that were previously possible. This additionally ensures that private messages are truly private.

Groups make use of 12 unique keys in total: Two permanent keypairs (encryption and signature), two group keypairs (encryption and signature), one session keypair (encryption), and one shared symmetric key (encryption).

The Tox ID/Tox public key is not used for any purpose. As such, neither peers in a given group nor in the group DHT can be matched with their Tox ID. In other words, there is no way of identifying a peer aside from their IP address, nickname, and group public key. (_Note: group nicknames can be different from the client's main nickname that their friends see_).

<a name="Permanent_keypairs" />

### Permanent keypairs

When a peer creates or joins a group they generate two permanent keypairs: an encryption keypair and a signature keypair, both of which are unique to the group. The two public keys are the only guaranteed way to identify a peer, and both keypairs will persist for as long as a peer remains in the group (even across client restarts). If a peer exits the group these keypairs will be lost forever.

This encryption keypair is not used for any encryption operations except for the initial handshake when connecting to another peer. For usage details on the signature key, see the [Moderation](#Moderation) section.

<a name="Session_keypair" />

### Session keypair/shared symmetric key

When two peers establish a connection they each generate a session encryption keypair and share one another's resulting public key. With their own session secret key and the other's session public key, they will both generate the same symmetric encryption key. This symmetric key will be used for all further encryption operations between them for the duration of the session.

The purpose of this extra key exchange is to prevent an adversary from decrypting messages from previous sessions in event that a secret encryption key becomes compromised. This is known as forward secrecy.

<a name="Group_keypairs" />

### Group keypairs

The group founder generates two additional permanent keypairs when the group is created: an encryption keypair, and a signature keypair. The public signature key is considered the **Chat ID** and is used as the group's permanent identifier, allowing other peers to join public groups via the DHT. Every peer in the group holds a copy of the group's public encryption key along with the public signature key/Chat ID.

The group secret keys are similar to the permanent keypairs in that they will persist across client restarts, but will be lost forever if the founder exits the group. This is particularly important as administration related functionality will not work without these keys. See the [Founders](#Founders) section for usage details.

<a name="Founders" />

## Founders

The peer who creates the group is the group's founder. Founders have a set of admin privileges, including:
* Promoting and demoting moderators
* The ability to kick moderators along-side non-moderators
* Setting the peer limit
* Setting the group's privacy state
* Setting group passwords

<a name="Shared_state" />

### Shared state

Groups contain a data structure called the **shared state** which is given to every peer who joins the group. Within this structure resides all data pertaining to the group that must only be modifiable by the group founder. This includes things like the group name, the group type, the peer limit, and the password. Additionally, the shared state holds a copy of the group founder's public encryption and signature keys, which is how other peers in the group are able to verify the identity of the group founder.

The shared state is signed by the founder using the group secret signature key. As the founder is the only peer who holds this secret key, the shared state can be shared with new peers and cryptographically verified even in the absence of the founder.

When the founder modifies the shared state, he increments the shared state version, signs the new shared state data with the group secret signature key, and broadcasts the new shared state data along with its signature to the entire group. When a peer receives this broadcast, he uses the group public signature key to verify that the data was signed with the group secret signature key, and also verifies that the new version is not older than the current version.

<a name="Moderation" />

## Moderation

The founder has the ability to promote other peers to the moderator role. Moderators have all the privileges of normal users. In addition, they have the power to kick peers whose role is below moderator, as well as set their roles to anything below moderator (see the [Group roles](#Group roles) section). Moderators may also modify the group topic. Moderators have no power over one another; only the founder can kick or change the role of a moderator.

<a name="Kicks" />

### Kicks

When a peer is kicked from the group, he will be disconnected from all group peers, his role will be set to user, and his chat instance will be left in a disconnected state. His public key will not be lost; he will be able to reconnect to the group with the same identity.

<a name="Moderator_list" />

### Moderator list

Each peer holds a copy of the **moderator list**, which is an array of public signature keys of peers who currently have the moderator role (including those who are offline). A hash (sha256) of this list called the **mod_list_hash** is stored in the shared state, which is itself signed by the founder using the group secret signature key. This allows the moderator list to be shared between untrusted peers, even in the absence of the founder, while maintaining moderator verifiability.

When the founder modifies the moderator list, he updates the mod_list_hash, increments the shared state version, signs the new shared state, broadcasts the new shared state data along with its signature to the entire group, then broadcasts the new moderator list to the entire group. When a peer receives this moderator list (having already verified the new shared state), he creates a hash of the new list and verifies that it is identical to the mod_list_hash.

<a name="Sanctions_list" />

### Sanctions list

Each peer holds a copy of the **sanctions list**. This list is comprised of peers who have been demoted to the observer role.

Entries contain the public key of the sanctioned peer, a timestamp of the time the entry was made, the public signature key of the peer who set the sanction, and a signature of the entry's data, which is signed by the peer who created the entry using their secret signature key. Individual entries are verified by ensuring that the entry's public signature key belongs to the founder or is present in the moderator list, and then verifying that the entry's data was signed by the owner of that key.

Although each individual entry can be verified, we still need a way to verify that the list as a whole is complete and identical for every peer, otherwise any peer would be able to remove entries arbitrarily, or replace the list with an older version. Therefore each peer holds a copy of the **sanctions list credentials**. This is a data structure that holds the version, a hash (sha256) of all sanctions list entries, plus the version, the public signature key of the last peer to have modified the sanctions list, and a signature of the hash which is created by that key.

When a moderator or founder modifies the sanctions list, he will increment the version, create a new hash, sign the hash+version with his secret signature key, and replace the old public signature key with his own. He will then broadcast the new changes (not the entire list) to the entire group along with the new credentials. When a peer receives this broadcast, he will verify that the new credentials version is not older than the current version and verify that the changes were made by a moderator or the founder. If adding an entry, he will verify that the entry was signed by the signature key of the entry's creator.

When the founder kicks or demotes a moderator, he will first go through the sanctions list and re-sign each entry made by that moderator using the founder key, then re-broadcast the sanctions list to the entire group. This is necessary to guarantee that all sanctions list entries and its credentials are signed by a current moderator or the founder at all times.

_Note: The sanctions list is not saved to the Tox save file, meaning that if the group ever becomes empty, the sanctions list will be reset. This is in contrast to the shared state and moderator list, which are both saved and will persist even if the group becomes empty._

<a name="Topics" />

## Topics

Founders and moderators have the ability to set the **topic**, which is simply an arbitrary string of characters. The integrity of a topic is maintained in a similar manner as sanctions entries, using a data structure called **topic_info**. This is a struct which contains the topic, a version, and the public key of the peer who set it.

When a peer modifies the topic, they will increment the version, sign the new topic+version with their secret signature key, replace the public key with their own, then broadcast the new topic_info data along with the signature to the entire group. When a peer receives this broadcast, they will first check if the public signature key of the setter either belongs to the founder, or is in the moderator list. They will then verify the signature using the setter's public signature key, and finally they will ensure that the version is not older than the current topic version.

If the moderator who set the current topic is kicked or demoted, the founder will re-sign the topic using his own signature key, and rebroadcast it to the entire group.

<a name="State_syncing" />

## State syncing

Peers send two unsigned 16-bit integers and three unsigned 32-bit integers along with their ping packets: Their peer count[1], a checksum of their peer list, their shared state version, their sanctions credentials version, and their topic version. If a peer receives a ping in which any of the versions are greater than their own, or if their peer list checksum does not match and their peer count is not greater than the peer count received, this indicates that they may be out of sync with the rest of the group. In this case they will send a sync request to the respective peer, with the appropriate sync flags set to indicate what group information they need.

Peers that are connected to the DHT also occasionally append their IP and port number to their ping packets for peers with which they do not have a direct UDP connection established. This gives priority to direct connections and ensures that TCP relays are used only as a fall-back, or when a peer explicitly forces a TCP connection.

[1] We use a "real" peer count, which is the number of confirmed peers in the peerlist (that is, peers who you have successfully handshaked and exchanged peer info with).

<a name="DHT_Announcements" />

## DHT Announcements

Public groupchats leverage the Tox DHT network in order to allow for groups that can be joined by anyone who possesses the Chat ID. Group announcements have the same underlying functionality as normal Tox friend announcements (including onion routing).