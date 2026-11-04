import os
import sys
import getpass
import subprocess
import urllib.request

BASE = os.path.expanduser("~/.kalyna")
JAR_NAME = "bcprov-jdk18on-1.78.1.jar"
JAR = os.path.join(BASE, JAR_NAME)
JAR_URL = ("https://repo1.maven.org/maven2/org/bouncycastle/"
           "bcprov-jdk18on/1.78.1/" + JAR_NAME)

JAVA_SRC = r'''
import org.bouncycastle.crypto.engines.DSTU7624Engine;
import org.bouncycastle.crypto.modes.KGCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

public class Kalyna {
    static final byte[] MAGIC = "KLN2".getBytes(StandardCharsets.US_ASCII);
    static final int MAC = 16, CHUNK = (1 << 20) - 64, ITER = 600000, HEADER = 80;

    static byte[] derive(char[] pw, byte[] salt) throws Exception {
        SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
        return f.generateSecret(new PBEKeySpec(pw, salt, ITER, 512)).getEncoded();
    }

    static byte[] run(boolean enc, byte[] key, byte[] nonce, byte[] aad,
                      byte[] data, int len) throws Exception {
        KGCMBlockCipher c = new KGCMBlockCipher(new DSTU7624Engine(512));
        c.init(enc, new AEADParameters(new KeyParameter(key), MAC * 8, nonce, aad));
        byte[] out = new byte[c.getOutputSize(len)];
        int n = c.processBytes(data, 0, len, out, 0);
        n += c.doFinal(out, n);
        return Arrays.copyOf(out, n);
    }

    static byte[] cat(byte[]... parts) {
        int t = 0;
        for (byte[] p : parts) t += p.length;
        byte[] r = new byte[t];
        int o = 0;
        for (byte[] p : parts) { System.arraycopy(p, 0, r, o, p.length); o += p.length; }
        return r;
    }

    static byte[] aadOf(byte[] header, byte[] c, boolean fin) throws Exception {
        return MessageDigest.getInstance("SHA-512")
                .digest(cat(header, c, new byte[]{(byte) (fin ? 1 : 0)}));
    }

    static byte[] ctr(long i) { return ByteBuffer.allocate(8).putLong(i).array(); }

    static int readFull(InputStream in, byte[] b) throws IOException {
        int t = 0;
        while (t < b.length) {
            int r = in.read(b, t, b.length - t);
            if (r < 0) break;
            t += r;
        }
        return t;
    }

    static void encrypt(String inPath, String outPath, char[] pw) throws Exception {
        SecureRandom rnd = new SecureRandom();
        byte[] salt = new byte[16], prefix = new byte[56];
        rnd.nextBytes(salt); rnd.nextBytes(prefix);
        byte[] header = cat(MAGIC, salt, prefix, ByteBuffer.allocate(4).putInt(CHUNK).array());
        byte[] key = derive(pw, salt);
        File tmp = new File(outPath + ".tmp");
        try (InputStream in = new BufferedInputStream(new FileInputStream(inPath), 1 << 16);
             OutputStream out = new BufferedOutputStream(new FileOutputStream(tmp), 1 << 16)) {
            out.write(header);
            byte[] cur = new byte[CHUNK];
            int curLen = readFull(in, cur);
            long i = 0;
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
                if (fin) break;
                curLen = readFull(in, cur);
                i++;
            }
        } catch (Exception e) {
            tmp.delete();
            throw e;
        }
        if (!tmp.renameTo(new File(outPath)))
            throw new IOException("No se pudo crear " + outPath);
    }

    static void decrypt(String inPath, String outPath, char[] pw) throws Exception {
        File tmp = new File(outPath + ".tmp");
        try (InputStream in = new BufferedInputStream(new FileInputStream(inPath), 1 << 16)) {
            byte[] header = new byte[HEADER];
            if (readFull(in, header) != HEADER
                    || !Arrays.equals(Arrays.copyOfRange(header, 0, 4), MAGIC))
                throw new IOException("Formato no reconocido");
            byte[] salt = Arrays.copyOfRange(header, 4, 20);
            byte[] prefix = Arrays.copyOfRange(header, 20, 76);
            int chunk = ByteBuffer.wrap(header, 76, 4).getInt();
            if (chunk <= 0 || chunk > (1 << 26)) throw new IOException("Cabecera invalida");
            byte[] key = derive(pw, salt);
            int sz = chunk + MAC;
            try (OutputStream out = new BufferedOutputStream(new FileOutputStream(tmp), 1 << 16)) {
                byte[] cur = new byte[sz], nxt = new byte[sz];
                int curLen = readFull(in, cur);
                long i = 0;
                while (true) {
                    int nxtLen = (curLen == sz) ? readFull(in, nxt) : 0;
                    boolean fin = nxtLen == 0;
                    byte[] c = ctr(i);
                    byte[] p = run(false, key, cat(prefix, c), aadOf(header, c, fin), cur, curLen);
                    if (fin) {
                        int e = p.length;
                        while (e > 0 && p[e - 1] == 0) e--;
                        if (e == 0 || p[e - 1] != (byte) 0x80) throw new IOException("Relleno invalido");
                        out.write(p, 0, e - 1);
                        break;
                    }
                    out.write(p);
                    byte[] t = cur; cur = nxt; nxt = t;
                    curLen = nxtLen;
                    i++;
                }
            }
            if (!tmp.renameTo(new File(outPath)))
                throw new IOException("No se pudo crear " + outPath);
        } catch (Exception e) {
            tmp.delete();
            throw e;
        }
    }

    public static void main(String[] a) {
        try {
            BufferedReader br = new BufferedReader(
                    new InputStreamReader(System.in, StandardCharsets.UTF_8));
            String line = br.readLine();
            char[] pw = (line == null ? "" : line).toCharArray();
            if (a[0].equals("c")) encrypt(a[1], a[2], pw);
            else decrypt(a[1], a[2], pw);
        } catch (Exception e) {
            System.err.println("ERROR: Contrasena incorrecta, archivo corrupto/modificado o fallo de E/S ("
                    + e.getClass().getSimpleName() + ": " + e.getMessage() + ")");
            System.exit(1);
        }
    }
}
'''


def preparar():
    os.makedirs(BASE, exist_ok=True)
    if not os.path.exists(JAR):
        print("Descargando Bouncy Castle...") urllib.request.urlretrieve(JAR_URL, JAR + ".part")
        os.replace(JAR + ".part", JAR)
    src = os.path.join(BASE, "Kalyna.java")
    cls = os.path.join(BASE, "Kalyna.class")
    actual = open(src).read() if os.path.exists(src) else ""
    if actual != JAVA_SRC or not os.path.exists(cls):
        with open(src, "w") as f:
            f.write(JAVA_SRC)
        print("Compilando...")
        subprocess.run(["javac", "-cp", JAR, "-d", BASE, src], check=True)
def ejecutar(modo, entrada, salida, password):
    r = subprocess.run(
        ["java", "-cp", JAR + os.pathsep + BASE, "Kalyna", modo, entrada, salida],
        input=(password + "\n").encode("utf-8"))
    if r.returncode != 0:
        sys.exit(1)
    print("Creado:", salida)
if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] not in ("c", "d"):
        sys.exit(__doc__)
    modo, ruta = sys.argv[1], sys.argv[2]
    if not os.path.isfile(ruta):
        sys.exit("No existe el archivo: " + ruta)
    if modo == "c":
        salida = ruta + ".enc"
    else:
        if not ruta.endswith(".enc"):
            sys.exit("El archivo debe terminar en .enc")
        salida = ruta[:-4]
    if os.path.exists(salida):
        sys.exit(salida + " ya existe; muévelo o bórralo")
    pw = getpass.getpass("Contraseña: ")
    if modo == "c" and getpass.getpass("Repite la contraseña: ") != pw:
        sys.exit("Las contraseñas no coinciden")
    preparar()
    ejecutar(modo, ruta, salida, pw)
