package sm2;

import base.Cipher;
import base.Util;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jcajce.provider.asymmetric.util.KeyUtil;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import java.io.IOException;
import java.math.BigInteger;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;

/**
 * Created by zhuxiaole on 2018/1/13.
 */
public class SM2Utils {
    //生成随机秘钥对
    public static void generateKeyPair(){
        SM2 sm2 = SM2.Instance();
        AsymmetricCipherKeyPair key = sm2.ecc_key_pair_generator.generateKeyPair();
        ECPrivateKeyParameters ecpriv = (ECPrivateKeyParameters) key.getPrivate();
        ECPublicKeyParameters ecpub = (ECPublicKeyParameters) key.getPublic();
        BigInteger privateKey = ecpriv.getD();
        ECPoint publicKey = ecpub.getQ();

        System.out.println("公钥: " + Util.byteToHex(publicKey.getEncoded()));
        System.out.println("私钥: " + Util.byteToHex(privateKey.toByteArray()));
    }

    //数据加密
    public static String encrypt(byte[] publicKey, byte[] data) throws IOException
    {
        if (publicKey == null || publicKey.length == 0)
        {
            return null;
        }

        if (data == null || data.length == 0)
        {
            return null;
        }

        byte[] source = new byte[data.length];
        System.arraycopy(data, 0, source, 0, data.length);

        Cipher cipher = new Cipher();
        SM2 sm2 = SM2.Instance();
        ECPoint userKey = sm2.ecc_curve.decodePoint(publicKey);

        ECPoint c1 = cipher.Init_enc(sm2, userKey);
        cipher.Encrypt(source);
        byte[] c3 = new byte[32];
        cipher.Dofinal(c3);

//      System.out.println("C1 " + Util.byteToHex(c1.getEncoded()));
//      System.out.println("C2 " + Util.byteToHex(source));
//      System.out.println("C3 " + Util.byteToHex(c3));
        //C1 C2 C3拼装成加密字串
        return Util.byteToHex(c1.getEncoded()) + Util.byteToHex(source) + Util.byteToHex(c3);

    }

    //数据解密
    public static byte[] decrypt(byte[] privateKey, byte[] encryptedData) throws IOException
    {
        if (privateKey == null || privateKey.length == 0)
        {
            return null;
        }

        if (encryptedData == null || encryptedData.length == 0)
        {
            return null;
        }
        //加密字节数组转换为十六进制的字符串 长度变为encryptedData.length * 2
        String data = Util.byteToHex(encryptedData);
        /***分解加密字串
         * （C1 = C1标志位2位 + C1实体部分128位 = 130）
         * （C3 = C3实体部分64位  = 64）
         * （C2 = encryptedData.length * 2 - C1长度  - C2长度）
         */
        byte[] c1Bytes = Util.hexToByte(data.substring(0,130));
        int c2Len = encryptedData.length - 97;
        byte[] c2 = Util.hexToByte(data.substring(130,130 + 2 * c2Len));
        byte[] c3 = Util.hexToByte(data.substring(130 + 2 * c2Len,194 + 2 * c2Len));

        SM2 sm2 = SM2.Instance();
        BigInteger userD = new BigInteger(1, privateKey);

        //通过C1实体字节来生成ECPoint
        ECPoint c1 = sm2.ecc_curve.decodePoint(c1Bytes);
        Cipher cipher = new Cipher();
        cipher.Init_dec(userD, c1);
        cipher.Decrypt(c2);
        cipher.Dofinal(c3);

        //返回解密结果
        return c2;
    }

    public static void main(String[] args) throws Exception
    {
        //生成密钥对
        generateKeyPair();

        String plainText = "ererfeiisgod";
        byte[] sourceData = plainText.getBytes();

        //下面的秘钥可以使用generateKeyPair()生成的秘钥内容
        // 国密规范正式私钥
        String prik = "3690655E33D5EA3D9A4AE1A1ADD766FDEA045CDEAA43A9206FB8C430CEFE0D94";
        // 国密规范正式公钥
        String pubk = "04F6E0C3345AE42B51E06BF50B98834988D54EBC7460FE135A48171BC0629EAE205EEDE253A530608178A98F1E19BB737302813BA39ED3FA3C51639D7A20C7391A";
        X509EncodedKeySpec publickey = new X509EncodedKeySpec(Util.hexToByte( "04F6E0C3345AE42B51E06BF50B98834988D54EBC7460FE135A48171BC0629EAE205EEDE253A530608178A98F1E19BB737302813BA39ED3FA3C51639D7A20C7391A"));
       // BCECPublicKey k = new BCECPublicKey();
        System.out.println("加密: ");
        String cipherText = SM2Utils.encrypt(Util.hexToByte(pubk), sourceData);
        System.out.println(cipherText);
        System.out.println("解密: ");
        plainText = new String(SM2Utils.decrypt(Util.hexToByte(prik), Util.hexToByte(cipherText)));
        System.out.println(plainText);
        //国密私钥转为证书对象
        PrivateKey p = new PrivateKey() {
                @Override
                public String getAlgorithm() {
                    return "SM2";
                }

                @Override
                public String getFormat() {
                    return "X.509";
                }

                @Override
                public byte[] getEncoded() {
                    X962Parameters params = new X962Parameters(DERNull.INSTANCE);
                    ECPrivateKey keyStructure = null;
                    keyStructure = new ECPrivateKey(this.getD(), params);

                    try {
                        return (new PrivateKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, params), (ASN1Encodable) keyStructure)).getEncoded("DER");
                    } catch (Exception var3) {
                        return null;
                    }
                }
                public BigInteger getD(){
                    return null;
                }
            };
        //国密公钥转为证书对象
         // KeyPair keyPair = this.kpg.generateKeyPair();
            PublicKey publicKey = new PublicKey() {
                @Override
                public String getAlgorithm() {
                    return "SM2";
                }

                @Override
                public String getFormat() {
                    return "X.509";
                }

                @Override
                public byte[] getEncoded() {
                    //DERObjectIdentifier info = new DERObjectIdentifier("1.2.156.10197.1.301");
                    DERObjectIdentifier info = new DERObjectIdentifier("1.2.840.113549.1.1.1");
//X9ObjectIdentifiers.id_ecPublicKey
                    SubjectPublicKeyInfo info1 = new SubjectPublicKeyInfo(new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, info), "040C6CEC619E8FE896A4C36B885F7EB21B76FB7C955091BF7D1E0FF1B4618A9037DEC4861D2C293F6F5BF9F257C1FF6609F3569FBE36955BA1329533F1D2A53A5A".getBytes());

                    try {
                        return info1.getEncoded("DER");
                    } catch (IOException var2) {
                        var2.printStackTrace();
                        return null;
                    }
                }
            };

    }
}
