package import1;


import base.SM2X509V3CertificateGenerator;
import crypto.SM2;
import crypto.SM2KeyPair;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECPoint;


import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;

/**
 * Created by zhuxiaole on 2018/1/13.
 */
public class BaseCert {
    /**
     * BouncyCastleProvider
     */
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     *
     */
    protected static KeyPairGenerator kpg = null;

    /**
     *
     */
    public BaseCert() {
        try {
            // 采用 RSA 非对称算法加密
            kpg = KeyPairGenerator.getInstance("RSA");
            // 初始化为 1023 位
            kpg.initialize(1024);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

    }

    /**
     * 生成 X509 证书
     *
     * @param user
     * @return
     */
    public X509Certificate generateCert(String user) throws InvalidKeyException {
        try { // 创建KeyStore
        KeyStore store = KeyStore.getInstance("PKCS12");
        store.load(null, null);
        X509Certificate cert = null;
        BigInteger num = new BigInteger("110123456789");

            KeyPair keyPair = this.kpg.generateKeyPair();
            // 公钥
            PublicKey pubKey1 =keyPair.getPublic();;//
            // 私钥
            PrivateKey priKey = keyPair.getPrivate();
        //ECPublicKey bcecPublicKey = new ECPublicKeyImpl(Util.hexToByte("04F6E0C3345AE42B51E06BF50B98834988D54EBC7460FE135A48171BC0629EAE205EEDE253A530608178A98F1E19"));
        //EncodedKeySpec publickey = new X509EncodedKeySpec(Util.hexToByte( "04F6E0C3345AE42B51E06BF50B98834988D54EBC7460FE135A48171BC0629EAE205EEDE253A530608178A98F1E19BB737302813BA39ED3FA3C51639D7A20C7391A"));

            SM2 sm02 = new SM2();
            SM2KeyPair keyPair1 = sm02.generateKeyPair();
            ECPoint publicKey=keyPair1.getPublicKey();
            BigInteger privateKey=keyPair1.getPrivateKey();


            ECPublicKey b = new ECPublicKey() {
                SM2 sm02 = new SM2();
                SM2KeyPair keyPair1 = sm02.generateKeyPair();
                public ECPoint getQ() {
                    return keyPair1.getPublicKey();
                }

                public ECParameterSpec getParameters() {
                    return null;
                }

                public String getAlgorithm() {
                    return "SM2";
                }

                public String getFormat() {
                    return "";
                }

                public byte[] getEncoded() {
                    return  keyPair1.getPublicKey().getEncoded();
                }
            };

             KeyFactory keyFactory = KeyFactory.getInstance("RSA");
           // PublicKey pubKey =  keyFactory.generatePublic(publickey);


        // X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
            SM2X509V3CertificateGenerator certGen = new SM2X509V3CertificateGenerator();
            // 设置序列号
            certGen.setSerialNumber(num);
            // 设置颁发者
            certGen.setIssuerDN(new X500Principal(CAConfig.CA_ROOT_ISSUER));
            // 设置有效期
            certGen.setNotBefore(new Date());
            certGen.setNotAfter(new Date());
            // 设置使用者
            certGen.setSubjectDN(new X500Principal(CAConfig.CA_DEFAULT_SUBJECT + user));
            // 公钥
            certGen.setPublicKey(b);
            // 签名算法
            certGen.setSignatureAlgorithm(CAConfig.SM3_SM2);
          // certGen.setSignatureAlgorithm(CAConfig.CA_SHA);

            cert = certGen.generate(priKey);
            store.setKeyEntry("alias", keyPair.getPrivate(),
                    "111111".toCharArray(),  new Certificate[] { cert});

            return cert;
        } catch (SignatureException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (CertificateEncodingException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (CertificateException e1) {
            e1.printStackTrace();
        }  catch (KeyStoreException e1) {
            e1.printStackTrace();
        } catch (IOException e1) {
            e1.printStackTrace();
        }


        return null;
    }
}