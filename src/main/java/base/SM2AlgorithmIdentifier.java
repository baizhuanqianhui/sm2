package base;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/**
 * Created by zhuxiaole on 2018/1/13.
 */
public class SM2AlgorithmIdentifier extends AlgorithmIdentifier {

    public SM2AlgorithmIdentifier(ASN1ObjectIdentifier algorithm) {
        super(algorithm);
    }

    public SM2AlgorithmIdentifier(ASN1ObjectIdentifier algorithm,ASN1Encodable parameters)
    {
        super(algorithm,parameters);
    }


    @Override
    public ASN1Primitive toASN1Primitive() {
        ASN1ObjectIdentifier algorithm = new ASN1ObjectIdentifier("1.2.156.10197.1.301");
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(algorithm);

        if (getParameters() != null)
        {
            v.add(getParameters());
        }

        return new DERSequence(v);
    }

}
