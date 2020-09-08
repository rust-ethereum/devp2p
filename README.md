# rust-devp2p

[![crates.io](https://img.shields.io/crates/v/devp2p.svg)](https://crates.io/crates/devp2p) [![Documentation](https://docs.rs/devp2p/badge.svg)](https://docs.rs/devp2p) [![Build Status](https://travis-ci.org/rust-ethereum/rust-devp2p.svg?branch=master)](https://travis-ci.org/rust-ethereum/rust-devp2p)

Rust implementation for devp2p networking protocol.

## Goals
- Make a general-purpose RLPx node implementation which can register sub-protocols.
- Add tools to help develop a customized subprotocol on top of RLPx stack.

## Design
[Read here](https://ethereum-magicians.org/t/eth1-architecture-working-group-first-call-for-proposals/4446/2)
