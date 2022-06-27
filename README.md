# ibc-harmony-client

IBC Harmony client is an IBC Client ([ICS-02](https://www.harmony.one/)) for validating [Harmony](https://www.harmony.one/) [FBFT](https://docs.harmony.one/home/general/technology/consensus).

This project is under development.

## Presumption

We presume the following:

- The target harmony network is after the Staking Epoch

## Overview

The client verifies a target shard header submitted and tracks its states for IBC such as the account roots with the height of the contract, the committees of each epoch, etc.

The client uses the account root and the storage proof submitted to perform membership or non-membership verification of a necessary commitment, such as whether a certain packet or ack exists on the target shard chain.

### Verification of beacon chain

This client verifies that the elected committee sufficiently signs each beacon header in the epoch of the header.

Harmony uses BLS signatures. The aggregated signatures and bitmap information for the signer's committee are submitted for verification. The quorum is also verified using the above bitmap and the voting power information held by the committee of that epoch.


The final header of each epoch contains the next epoch's committee information as a shard state. The client needs to be updated with this last header each time an epoch is updated.

### Verification of shard chain

The client verifies the existence of a beacon header with a valid [Crosslink](https://docs.harmony.one/home/general/technology/sharding#crosslinks) to the shard header.
This beacon header is verified by the signature of the committee as described above.

### Verification of membership/non-membership

The client receives the storage proof of [MPT](https://ethereum.org/en/developers/docs/data-structures-and-encoding/patricia-merkle-trie/) for a specific commitment at a certain height and verifies it with the account root of the already submitted target shard chain.

## Status

We will develop the specification for this client in the future.
