package import1;

import org.bouncycastle.util.encoders.Base64;

import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

/**
 * Created by zhuxiaole on 2018/1/13.
 */
public class GenerateCa {
    private static String certPath = "d:/sm2.cer";

    public static void main(String[] args) {
        // 导出为 cer 证书
        try {
        BaseCert baseCert = new BaseCert();
        X509Certificate cert = baseCert.generateCert("Lee");
        System.out.println(cert.toString());


            FileOutputStream fos = new FileOutputStream(certPath);
            fos.write(Base64.encode(cert.getEncoded()));
            fos.close();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (CertificateEncodingException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
    }
}
