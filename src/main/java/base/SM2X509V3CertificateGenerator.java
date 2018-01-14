package base;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.jcajce.provider.asymmetric.x509.CertificateFactory;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.util.Strings;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import sun.security.jca.GetInstance;

import javax.security.auth.x500.X500Principal;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;

/**
 * Created by zhuxiaole on 2018/1/13.
 */
public class SM2X509V3CertificateGenerator extends X509V3CertificateGenerator {
    private V3TBSCertificateGenerator tbsGen;
    private ASN1ObjectIdentifier        sigOID;
    private AlgorithmIdentifier sigAlgId;
    private String  signatureAlgorithm;
    private final CertificateFactory certificateFactory = new CertificateFactory();

    public SM2X509V3CertificateGenerator() {
      //  super();
        tbsGen = new V3TBSCertificateGenerator();
   //     extGenerator = new X509ExtensionsGenerator();
    }
    /**
     * set the serial number for the certificate.
     */
    public void setSerialNumber(
            BigInteger serialNumber)
    {
        if (serialNumber.compareTo(BigInteger.ZERO) <= 0)
        {
            throw new IllegalArgumentException("serial number must be a positive integer");
        }

        tbsGen.setSerialNumber(new ASN1Integer(serialNumber));
    }
    /**
     * Set the issuer distinguished name - the issuer is the entity whose private key is used to sign the
     * certificate.
     */
    public void setIssuerDN(
            X500Principal issuer)
    {
        try
        {
            tbsGen.setIssuer(new X509Principal(issuer.getEncoded()));
        }
        catch (IOException e)
        {
            throw new IllegalArgumentException("can't process principal: " + e);
        }
    }
    public void setNotBefore(
            Date date)
    {
        tbsGen.setStartDate(new Time(date));
    }

    public void setNotAfter(
            Date    date)
    {
        tbsGen.setEndDate(new Time(date));
    }
    /**
     * Set the subject distinguished name. The subject describes the entity associated with the public key.
     */
    public void setSubjectDN(
            X500Principal   subject)
    {
        try
        {
            tbsGen.setSubject(new X509Principal(subject.getEncoded()));
        }
        catch (IOException e)
        {
            throw new IllegalArgumentException("can't process principal: " + e);
        }
    }
    public void setPublicKey(
            PublicKey key)
            throws IllegalArgumentException
    {
        try
        {
            tbsGen.setSubjectPublicKeyInfo(
                    SubjectPublicKeyInfo.getInstance(new ASN1InputStream(key.getEncoded()).readObject()));
        }
        catch (Exception e)
        {
            throw new IllegalArgumentException("unable to process key - " + e.toString());
        }
    }

    @Override
    public void setSignatureAlgorithm(String  signatureAlgorithm) {


        this.signatureAlgorithm = signatureAlgorithm;

        try
        {
            signatureAlgorithm = Strings.toUpperCase(signatureAlgorithm);

            ASN1ObjectIdentifier algorithm = new ASN1ObjectIdentifier("1.2.156.10197.1.301");

            SM2AlgorithmIdentifier sm2AlgorithmIdentifier = new SM2AlgorithmIdentifier(algorithm);

            sigOID =algorithm;
        }
        catch (Exception e)
        {
            throw new IllegalArgumentException("Unknown signature type requested: " + signatureAlgorithm);
        }

        sigAlgId =  new AlgorithmIdentifier(sigOID, DERNull.INSTANCE);

        tbsGen.setSignature(sigAlgId);
    }
    @Override
    public X509Certificate generate(
            PrivateKey      key)
            throws CertificateEncodingException, IllegalStateException, NoSuchAlgorithmException, SignatureException, InvalidKeyException
    {
        return generate(key, (SecureRandom)null);
    }
    public X509Certificate generate(
            PrivateKey      key,
            SecureRandom    random)
            throws CertificateEncodingException, IllegalStateException, NoSuchAlgorithmException, SignatureException, InvalidKeyException
    {
        TBSCertificate tbsCert = generateTbsCert();
        byte[] signature;

       /* try
        {
            Signature sig;

            if (sigOID == null)
            {
                throw new IllegalStateException("no signature algorithm specified");
            }
            sig = Signature.getInstance(signatureAlgorithm);

            if (random != null)
            {
                sig.initSign(key, random);
            }
            else
            {
                sig.initSign(key);
            }

            sig.update(tbsCert.toASN1Primitive().getEncoded(ASN1Encoding.DER));

            signature = sig.sign();

        }
        catch (IOException e)
        {
            throw new CertificateEncodingException("exception encoding TBS cert", e);
        }
*/
        try
        {
            return generateJcaObject(tbsCert, null);
        }
        catch (Exception e)
        {
            throw new CertificateEncodingException("exception producing certificate object", e);
        }
    }
    private TBSCertificate generateTbsCert()
    {

        return tbsGen.generateTBSCertificate();
    }
    private X509Certificate generateJcaObject(TBSCertificate tbsCert, byte[] signature)
            throws Exception
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(tbsCert);
        v.add(sigAlgId);
        v.add(new DERBitString("04F6E0C3345AE42B51E06BF50B98834988D54EBC7460FE135A48171BC0629EAE205EEDE253A530608178A98F1E19BB737302813BA39ED3FA3C51639D7A20C7391A".getBytes()));

        return (X509Certificate)certificateFactory.engineGenerateCertificate(
                new ByteArrayInputStream(new DERSequence(v).getEncoded(ASN1Encoding.DER)));
    }
}
