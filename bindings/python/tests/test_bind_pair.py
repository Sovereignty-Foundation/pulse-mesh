# SPDX-License-Identifier: LicenseRef-Proprietary
# Copyright (c) 2026 Sovereignty Foundation
"""Tests for pulse_wire.bind_pair: a Sender and a Receiver on one UDP
socket, so a reply sent to the address a datagram came from reaches the
program that sent it, as a home router (NAT) requires."""

import pulse_wire as pw


def data_pulse():
    p = pw.Pulse()
    p.instruction = pw.Instruction.DATA
    return p


def test_pair_shares_one_port():
    tx, rx = pw.bind_pair("127.0.0.1:0")
    assert tx.local_addr() == rx.local_addr()


def test_reply_to_the_observed_source_comes_back():
    # A requester and a responder, each on one socket.
    req_tx, req_rx = pw.bind_pair("127.0.0.1:0")
    resp_tx, resp_rx = pw.bind_pair("127.0.0.1:0")
    req_rx.set_read_timeout_ms(2000)
    resp_rx.set_read_timeout_ms(2000)

    req_tx.send_to(1, data_pulse(), b"ping", resp_rx.local_addr())
    _pulse, envelope, meta = resp_rx.recv()
    assert envelope == b"ping"
    # The request came from the requester's one port.
    assert meta.peer == req_rx.local_addr()

    # The responder answers the address it saw, from its own one port.
    resp_tx.send_to(2, data_pulse(), b"pong", meta.peer)
    _pulse, envelope, meta = req_rx.recv()
    assert envelope == b"pong"
    assert meta.peer == resp_rx.local_addr()
