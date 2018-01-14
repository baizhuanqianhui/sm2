package import1;

import org.bouncycastle.util.encoders.Base64;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;


/**
 * Created by zhuxiaole on 2018/1/14.
 */
public class CertUtil {
    /**
     * @author God
     * @cerPath Java读取Cer证书信息
     * @throws Exception
     * @return X509Cer对象
     */
    public static X509Certificate getX509CerCate(String cerPath) throws Exception {
        X509Certificate x509Certificate = null;
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        FileInputStream fileInputStream = new FileInputStream(cerPath);
        //创建缓冲数组
        byte[] buf = new byte[2048];
        //用数组去读取数据,此时read()返回，读取的数量，当读到空时，返回-1.
        String key="";
        while (fileInputStream.read(buf)!=-1) {
            key +=new String(buf);

        }
        System.out.println("内容："+key);
       // fileInputStream.
      //"MIICHjCCAYagAwIBAgIFGaPemRUwDAYIKoEcz1UBgi0FADBUMQ4wDAYDVQQDEwVTSUNDQTELMAkGA1UECxMCU0MxDjAMBgNVBAoTBVNJQ0NBMQswCQYDVQQHEwJCSjELMAkGA1UECBMCQkoxCzAJBgNVBAYTAkNOMB4XDTE4MDExNDA1NTkzMloXDTE4MDExNDA1NTkzMlowUjEMMAoGA1UEAxMDTGVlMQswCQYDVQQLEwJTQzEOMAwGA1UEChMFU0lDQ0ExCzAJBgNVBAcTAkJKMQswCQYDVQQIEwJCSjELMAkGA1UEBhMCQ04wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAIU1O4V0WgLR2/PkdcQ1izMcERIho//hMgOxTtwwqAWhWJDUofuGqysb7by3uV+GDcnv8tI6ZCSmg+kl30Pi3Gc3wnBmQLcEfJTalEcc0xwBNzNB7Rwqt/vCZURFbqXM1p3fcP0FHS/xNhCp3O+CzZPSlXsJmyP0Pqx6mg1hqWpjAgMBAAEwDAYIKoEcz1UBgi0FAAOBgwAwNEY2RTBDMzM0NUFFNDJCNTFFMDZCRjUwQjk4ODM0OTg4RDU0RUJDNzQ2MEZFMTM1QTQ4MTcxQkMwNjI5RUFFMjA1RUVERTI1M0E1MzA2MDgxNzhBOThGMUUxOUJCNzM3MzAyODEzQkEzOUVEM0ZBM0M1MTYzOUQ3QTIwQzczOTFB";

        InputStream sbs = new ByteArrayInputStream( Base64.decode(key.trim()));
        x509Certificate = (X509Certificate) certificateFactory.generateCertificate(sbs);
        fileInputStream.close();
        System.out.println("读取Cer证书信息...");
        System.out.println("x509Certificate_SerialNumber_序列号___:"+x509Certificate.getSerialNumber());
        System.out.println("x509Certificate_getIssuerDN_发布方标识名___:"+x509Certificate.getIssuerDN());
        System.out.println("x509Certificate_getSubjectDN_主体标识___:"+x509Certificate.getSubjectDN());
        System.out.println("x509Certificate_getSigAlgOID_证书算法OID字符串___:"+x509Certificate.getSigAlgOID());
        System.out.println("x509Certificate_getNotBefore_证书有效期___:"+x509Certificate.getNotAfter());
        System.out.println("x509Certificate_getSigAlgName_签名算法___:"+x509Certificate.getSigAlgName());
        System.out.println("x509Certificate_getVersion_版本号___:"+x509Certificate.getVersion());
        System.out.println("x509Certificate_getPublicKey_公钥___:"+x509Certificate.getPublicKey());
        System.out.println("x509Certificate_getPublicKey_签名___:"+new String(x509Certificate.getSignature(), "utf-8"));
        return x509Certificate;
    }
    public static void main(String[] args) throws Exception {
        getX509CerCate("d:/sm2.cer");
    }
}
