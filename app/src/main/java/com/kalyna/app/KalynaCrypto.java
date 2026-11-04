package com.kalyna.app;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.PBEParametersGenerator;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.engines.DSTU7624Engine;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.modes.KGCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Kalyna-512 (DSTU 7624:2014) en modo KGCM, por contraseña, por trozos.
 * Formato compatible con kalyna2.py (Termux): cabecera "KLN2".
 */
public final class KalynaCrypto {

    public interface Progress {
        /** Bytes de entrada ya procesados. */
        void onBytes(long done);
    }

    private static final byte[] MAGIC = "KLN2".getBytes(StandardCharsets.US_ASCII);
    private static final int MAC = 16;
    private static final int CHUNK = (1 << 20) - 64;
    private static final int ITER = 600000;
    private static final int HEADER = 80;

    private KalynaCrypto() {}

    private static byte[] derive(char[] pw, byte[] salt) {
        PKCS5S2ParametersGenerator g = new PKCS5S2ParametersGenerator(new SHA512Digest());
        g.init(PBEParametersGenerator.PKCS5PasswordToUTF8Bytes(pw), salt, ITER);
        return ((KeyParameter) g.generateDerivedParameters(512)).getKey();
    }

    private static byte[] run(boolean enc, byte[] key, byte[] nonce, byte[] aad,
                              byte[] data, int len) throws InvalidCipherTextException {
        KGCMBlockCipher c = new KGCMBlockCipher(new DSTU7624Engine(512));
        c.init(enc, new AEADParameters(new KeyParameter(key), MAC * 8, nonce, aad));
        byte[] out = new byte[c.getOutputSize(len)];
        int n = c.processBytes(data, 0, len, out, 0);
        n += c.doFinal(out, n);
        return Arrays.copyOf(out, n);
    }

    private static byte[] cat(byte[]... parts) {
        int t = 0;
        for (byte[] p : parts) t += p.length;
        byte[] r = new byte[t];
        int o = 0;
        for (byte[] p : parts) {
            System.arraycopy(p, 0, r, o, p.length);
            o += p.length;
        }
        return r;
    }

    private static byte[] ctr(long i) {
        return ByteBuffer.allocate(8).putLong(i).array();
    }

    private static byte[] aadOf(byte[] header, byte[] c, boolean fin) throws IOException {
        try {
            return MessageDigest.getInstance("SHA-512")
                    .digest(cat(header, c, new byte[]{(byte) (fin ? 1 : 0)}));
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IOException(e);
        }
    }

    private static int readFull(InputStream in, byte[] b) throws IOException {
        int t = 0;
        while (t < b.length) {
            int r = in.read(b, t, b.length - t);
            if (r < 0) break;
            t += r;
        }
        return t;
    }

    public static void encrypt(InputStream in, OutputStream out, char[] pw, Progress prog)
            throws IOException {
        try {
            SecureRandom rnd = new SecureRandom();
            byte[] salt = new byte[16], prefix = new byte[56];
            rnd.nextBytes(salt);
            rnd.nextBytes(prefix);
            byte[] header = cat(MAGIC, salt, prefix, ByteBuffer.allocate(4).putInt(CHUNK).array());
            byte[] key = derive(pw, salt);
            if (prog != null) prog.onBytes(0);
            out.write(header);
            byte[] cur = new byte[CHUNK];
            int curLen = readFull(in, cur);
            long i = 0, done = 0;
            while (true) {
                boolean fin = curLen < CHUNK;
                byte[] plain = cur;
                int plen = CHUNK;
                if (fin) {
                    plen = (curLen / 64 + 1) * 64;
                    plain = new byte[plen];
                    System.arraycopy(cur, 0, plain, 0, curLen);
                    plain[curLen] = (byte) 0x80;
                }
                byte[] c = ctr(i);
                out.write(run(true, key, cat(prefix, c), aadOf(header, c, fin), plain, plen));
                done += curLen;
                if (prog != null) prog.onBytes(done);
                if (fin) break;
                curLen = readFull(in, cur);
                i++;
            }
            out.flush();
        } catch (InvalidCipherTextException e) {
            throw new IOException("Error de cifrado: " + e.getMessage());
        }
    }

    public static void decrypt(InputStream in, OutputStream out, char[] pw, Progress prog)
            throws IOException {
        try {
            byte[] header = new byte[HEADER];
            if (readFull(in, header) != HEADER
                    || !Arrays.equals(Arrays.copyOfRange(header, 0, 4), MAGIC)) {
                throw new IOException("Formato no reconocido (no es un archivo .enc de Kalyna)");
            }
            byte[] salt = Arrays.copyOfRange(header, 4, 20);
            byte[] prefix = Arrays.copyOfRange(header, 20, 76);
            int chunk = ByteBuffer.wrap(header, 76, 4).getInt();
            if (chunk <= 0 || chunk > (1 << 26) || chunk % 64 != 0) {
                throw new IOException("Cabecera inválida");
            }
            byte[] key = derive(pw, salt);
            if (prog != null) prog.onBytes(HEADER);
            int sz = chunk + MAC;
            byte[] cur = new byte[sz], nxt = new byte[sz];
            int curLen = readFull(in, cur);
            long i = 0, done = HEADER;
            while (true) {
                int nxtLen = (curLen == sz) ? readFull(in, nxt) : 0;
                boolean fin = nxtLen == 0;
                byte[] c = ctr(i);
                byte[] p = run(false, key, cat(prefix, c), aadOf(header, c, fin), cur, curLen);
                if (fin) {
                    int e = p.length;
                    while (e > 0 && p[e - 1] == 0) e--;
                    if (e == 0 || p[e - 1] != (byte) 0x80) {
                        throw new IOException("Relleno inválido");
                    }
                    out.write(p, 0, e - 1);
                    done += curLen;
                    if (prog != null) prog.onBytes(done);
                    break;
                }
                out.write(p);
                done += curLen;
                if (prog != null) prog.onBytes(done);
                byte[] t = cur;
                cur = nxt;
                nxt = t;
                curLen = nxtLen;
                i++;
            }
            out.flush();
        } catch (InvalidCipherTextException | IllegalArgumentException e) {
            throw new IOException("Contraseña incorrecta o archivo corrupto/modificado");
        }
    }
}
