package keys;

import org.apache.commons.io.FileUtils;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.pgpainless.PGPainless;
import org.pgpainless.key.generation.KeyRingTemplates;
import org.pgpainless.key.generation.type.rsa.RsaLength;

import java.io.*;
import java.nio.charset.Charset;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;

public class PGPPainlessUtil {

    public void createKeyRing() throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IOException {
        KeyRingTemplates keyRingTemplates = new KeyRingTemplates();
        //PGPSecretKeyRing pgpSecretKeyRing = keyRingTemplates.simpleRsaKeyRing("apple-corps@example.com",RsaLength._4096,"test-password");
        PGPSecretKeyRing pgpSecretKeyRing = keyRingTemplates.modernKeyRing("apple-corps@example.com","test-password");
        String armored = PGPainless.asciiArmor(pgpSecretKeyRing);
        ByteArrayOutputStream binary = new ByteArrayOutputStream();
        pgpSecretKeyRing.encode(binary);

        FileUtils.writeStringToFile(
                new File("armored-secret-key.asc"),
                armored,
                Charset.forName("UTF8"));

        try(OutputStream outputStream = new FileOutputStream("secret-key")){
            binary.writeTo(outputStream);
            outputStream.close();
        } finally {
            binary.close();
        }

        PGPPublicKeyRing pgpKeyRing = PGPainless.extractCertificate(pgpSecretKeyRing);
        String armoredPublicCertificateKeyRing = PGPainless.asciiArmor(pgpKeyRing);
        ByteArrayOutputStream binary2 = new ByteArrayOutputStream();
        pgpKeyRing.encode(binary2);

        FileUtils.writeStringToFile(
                new File("public-key.asc"),
                armoredPublicCertificateKeyRing,
                Charset.forName("UTF8"));

        try (OutputStream outputStream2 = new FileOutputStream("public-key")){
            binary2.writeTo(outputStream2);
            outputStream2.close();
        } finally {
            binary2.close();
        }

    }


}