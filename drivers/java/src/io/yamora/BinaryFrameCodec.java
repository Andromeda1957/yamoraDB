package io.yamora;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;

/** Independent strict v1 framing. Validate advertised sizes before allocation. */
public final class BinaryFrameCodec {
    public static final int HELLO = 1, REQUEST = 2, RESPONSE = 3, DATA = 4, END = 5,
            CANCEL = 6, ERROR = 7, PING = 8, PONG = 9, GOAWAY = 10;
    private BinaryFrameCodec() {}
    public record Frame(int type, long stream, byte[] payload) {
        public Frame { payload = payload.clone(); }
        @Override public byte[] payload() { return payload.clone(); }
        @Override public String toString() { return "BinaryFrame[redacted]"; }
    }
    private static void valid(int type, long stream, long length, int cap) throws BinaryException {
        if (cap < 4096 || cap > 65536 || length < 0 || length > cap || type < 1 || type > 10
                || stream < 0 || stream > 0xffff_ffffL) throw BinaryException.protocol();
        boolean control = type == HELLO || type == PING || type == PONG || type == GOAWAY;
        if (control ? stream != 0 : stream == 0 || (stream & 1) == 0) throw BinaryException.protocol();
        switch (type) {
            case HELLO -> { if (length != 12) throw BinaryException.protocol(); }
            case REQUEST, RESPONSE -> { if (length < 1 || length > 2048) throw BinaryException.protocol(); }
            case DATA -> { if (length == 0) throw BinaryException.protocol(); }
            case END, CANCEL, GOAWAY -> { if (length != 0) throw BinaryException.protocol(); }
            case ERROR -> { if (length != 4) throw BinaryException.protocol(); }
            case PING, PONG -> { if (length != 8) throw BinaryException.protocol(); }
            default -> throw BinaryException.protocol();
        }
    }
    public static Frame read(InputStream input, int cap) throws IOException {
        byte[] header = exact(input, 16);
        ByteBuffer buffer = ByteBuffer.wrap(header);
        if (buffer.getInt() != 0x594d4246 || buffer.get() != 1) throw BinaryException.protocol();
        int type = buffer.get() & 255;
        if (buffer.getShort() != 0) throw BinaryException.protocol();
        long stream = Integer.toUnsignedLong(buffer.getInt()), size = Integer.toUnsignedLong(buffer.getInt());
        valid(type, stream, size, cap);
        byte[] payload = exact(input, (int) size);
        if (type == ERROR && ByteBuffer.wrap(payload).getInt() == 0) throw BinaryException.protocol();
        return new Frame(type, stream, payload);
    }
    private static byte[] exact(InputStream input, int size) throws IOException {
        byte[] result = new byte[size]; int offset = 0;
        while (offset < size) {
            int n = input.read(result, offset, size - offset);
            if (n < 0) throw new java.io.EOFException("incomplete binary frame");
            if (n == 0) throw BinaryException.protocol();
            offset += n;
        }
        return result;
    }
    public static void write(OutputStream output, int type, long stream, byte[] bytes, int cap) throws IOException {
        write(output, type, stream, bytes, 0, bytes.length, cap);
    }
    static void write(OutputStream output, int type, long stream, byte[] bytes, int offset, int length, int cap) throws IOException {
        valid(type, stream, length, cap);
        if (type == ERROR && (length != 4 || ByteBuffer.wrap(bytes, offset, length).getInt() == 0)) throw BinaryException.protocol();
        byte[] header = ByteBuffer.allocate(16).putInt(0x594d4246).put((byte) 1).put((byte) type).putShort((short) 0)
                .putInt((int) stream).putInt(length).array();
        output.write(header); output.write(bytes, offset, length);
    }
}
