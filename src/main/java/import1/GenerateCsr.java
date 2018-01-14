package import1;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.util.encoders.Base64;


import java.io.IOException;
import java.security.*;

/**
 * Created by zhuxiaole on 2018/1/14.
 */
public class GenerateCsr {
    public static String genCSR(String subject, String alg, String provider, byte[] pkdata) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException,OperatorCreationException {

        String signalg = "";

        int alglength = 0;

        String keyAlg = "";

        String hexString;


        if (alg.toUpperCase().equals("RSA1024")) {

            signalg = "SHA1WithRSA";

            alglength = 1024;

            keyAlg = "RSA";

        } else if (alg.toUpperCase().equals("RSA2048")) {

            // signalg = "SHA1WithRSA";

            signalg = "1.2.840.10045.4.1";

            alglength = 2048;

            keyAlg = "RSA";

        } else if (alg.toUpperCase().equals("SM2")) {

            // signalg = "ECDSAWITHSHA1";

            signalg = "SHA256WITHECDSA";

            alglength = 256;

            keyAlg = "EC";

        }

        org.bouncycastle.jce.provider.BouncyCastleProvider bouncyCastleProvider = new org.bouncycastle.jce.provider.BouncyCastleProvider();

        Provider t[] = Security.getProviders();

        Security.addProvider(bouncyCastleProvider);

        Provider t1[] = Security.getProviders();

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(keyAlg);
        keyGen.initialize(alglength);

        KeyPair kp = keyGen.generateKeyPair();

        // [48, 89, 48, 19, 6, 7, 42, -122, 72, -50, 61, 2, 1, 6, 8, 42, -122,

        // 72, -50, 61, 3, 1, 7, 3, 66]
        byte[] heradByte = new byte[] { 48, 89, 48, 19, 6, 7, 42, -122, 72, -50, 61, 2, 1, 6, 8, 42, -122, 72, -50, 61, 3, 1, 7, 3, 66, 0, 4 };

        byte[] data = byteMerger(heradByte, pkdata);

        PKCS10CertificationRequestBuilder builder = null;
        builder = new PKCS10CertificationRequestBuilder(new X500Name(subject), SubjectPublicKeyInfo.getInstance(data));

        JcaContentSignerBuilder jcaContentSignerBuilder = new JcaContentSignerBuilder(signalg);

        // jcaContentSignerBuilder.setProvider("BC");

        ContentSigner contentSigner = jcaContentSignerBuilder.build(kp.getPrivate());

        PKCS10CertificationRequest Request = builder.build(contentSigner);

        byte[] encoded2 = new byte[0];
        try {
            encoded2 = Request.getEncoded();
        } catch (IOException e) {
            e.printStackTrace();
        }

        hexString = new String(Base64.encode(encoded2));

        System.out.println(hexString);

        return hexString;

    }

    public static byte[] byteMerger(byte[] byte_1, byte[] byte_2) {
        byte[] byte_3 = new byte[byte_1.length + byte_2.length];
        System.arraycopy(byte_1, 0, byte_3, 0, byte_1.length);
        System.arraycopy(byte_2, 0, byte_3, byte_1.length, byte_2.length);
        return byte_3;
    }

    public static void main(String[] args) throws Exception
    {
        try {

            String dn = "CN=dfg, OU=aert, O=45y, L=sdfg, ST=fg, C=CN";

            try {

                String pkStr = "AAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAv/pInHHFzGAdhIRGDKOc2bjq9I3SUGIOIcMRwgMSpqEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIWXe67pEetAHBkEPY2Mi5B1TLu0+fH0z5gosfV21aUO";

                byte[] pkdata = Base64.decode(pkStr);

                byte[] x = new byte[32];

                byte[] y = new byte[32];

                System.arraycopy(pkdata, 36, x, 0, 32);

                System.arraycopy(pkdata, 36 + 32 + 32, y, 0, 32);

                byte[] data = byteMerger(x, y);

                genCSR(dn, "SM2", "CA", data);

            } catch (OperatorCreationException e) {

                // TODO Auto-generated catch block

                e.printStackTrace();

            }

        } catch (InvalidKeyException e) {

            // TODO Auto-generated catch block

            e.printStackTrace();

        } catch (NoSuchAlgorithmException e) {

            // TODO Auto-generated catch block

            e.printStackTrace();

        } catch (NoSuchProviderException e) {

            // TODO Auto-generated catch block

            e.printStackTrace();

        } catch (SignatureException e) {

            // TODO Auto-generated catch block

            e.printStackTrace();

        }
    }
}
