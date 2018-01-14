package import1;

import base.Util;
import org.bouncycastle.util.encoders.Base64;

import java.io.*;
import java.math.BigInteger;
import java.security.cert.X509Certificate;

/**
 * Created by zhuxiaole on 2018/1/14.
 */
public class GenerateSm2 {
    /**
     * 导出私钥到本地
     *
     * @param privateKey
     * @param path
     */
    public void exportPrivateKey(byte[] privateKey, String path) {
        try {
            System.out.println(new String(privateKey, "utf-8"));
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }


        FileOutputStream fos = null;
        try {
            fos = new FileOutputStream(path);
            fos.write(Base64.encode(privateKey));
            fos.close();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    public static void main(String[] args) throws UnsupportedEncodingException {
        GenerateSm2 sm2 = new GenerateSm2();
        sm2.exportPrivateKey("3690655E33D5EA3D9A4AE1A1ADD766FDEA045CDEAA43A9206FB8C430CEFE0D94".getBytes(), "D:/privatekey.sm2");
    }
}
