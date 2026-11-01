package io.yamora;

/** Peer negotiated only schema 1. No operation REQUEST has been sent. */
public final class BinaryUnsupportedPeerException extends BinaryException {
    private static final long serialVersionUID = 1L;
    BinaryUnsupportedPeerException() { super(Kind.PROTOCOL, 0); }
}
