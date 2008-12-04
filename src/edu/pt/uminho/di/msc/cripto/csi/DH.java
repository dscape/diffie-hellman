/*
 * DH.java
 *
 * Created on November 27, 2007
 */
package edu.pt.uminho.di.msc.cripto.csi;

import java.math.BigInteger;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.X509EncodedKeySpec;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;

/**
 *
 * Defines a Diffie-Hellman implementation using X509 encoding specification.
 * 
 * @author ramigs [ramigs<at>gmail.com]
 * @author dscape [http://nunojob.pt.to; nunojobpinto<at>gmail.com]
 */
public class DH {

    private static final BigInteger P = new BigInteger(
            "9949409665013933710618693397761851397414627483156676817958175" +
            "9037259788798151499814653951492724365471316253651463342255785" +
            "3117486029224587952013824453234999316254512726001731801361232" +
            "4544120413351580049591724201186355872172330366152337257247721" +
            "1620144038809673692512025566673746993593384600667047373692203" +
            "583");
    private static final BigInteger G = new BigInteger(
            "4415740483796032876887268067768680265099916322676669479765081" +
            "0379076416463147265401084491113667624054557335394761604876882" +
            "4469249298406819901069743149350155015713330247731724403524753" +
            "5875066821344460735387275465080503191286669211981937704190164" +
            "2732455911509867728218394542745330014071040326856846990119719" +
            "675");
    public static final int USE_DEF_DH_PARAMS = 1;
    public static final int GENERATE_DH_PARAMS = 2;
    public static final String ALGORITHM = "DH";
    private DHParameterSpec dhSpec;
    private DHPublicKey publicKey;
    private KeyAgreement ka;
    private byte[] publicKeyEncoding;
    private boolean failedPublicKeyGen;

    public DH() throws Exception {
        dhSpec = new DHParameterSpec(P, G);
        init();
    }

    public DH(int mode) throws Exception {
        switch (mode) {
            case 2:
                dhSpec = generateDhParams();
                if (dhSpec == null) {
                    dhSpec = new DHParameterSpec(P, G);
                }
                break;
            default:
                dhSpec = new DHParameterSpec(P, G);
                break;
        }
        init();
    }

    public DH(DHParameterSpec dhSpec) throws Exception {
        this.dhSpec = dhSpec;
        init();
    }

    private void init() throws Exception {
        failedPublicKeyGen = false;
        generatePublicKeyEncoding();
        generatePublicKey();
    }

    public DHPublicKey getDHPublicKey() {
        return publicKey;
    }

    protected KeyAgreement getDHKeyAgreement(){
        return ka;
    }

    private DHParameterSpec generateDhParams() {
        DHParameterSpec spec = null;
        try {
            AlgorithmParameterGenerator algGen =
                    AlgorithmParameterGenerator.getInstance("DH");
            algGen.init(512);
            AlgorithmParameters params = algGen.generateParameters();
            spec = (DHParameterSpec) params
                    .getParameterSpec(DHParameterSpec.class);
        } catch (Exception ex) {
            Logger.getLogger(DH.class.getName()).log(Level.WARNING, null, ex);
        } finally {
            return spec;
        }
    }

    private void generatePublicKey() throws Exception {
        if (publicKeyEncoding == null) {
            generatePublicKeyEncoding();
        }

        publicKey = null;
        try {
            KeyFactory kf = KeyFactory.getInstance(ALGORITHM);
            X509EncodedKeySpec x509KeySpec =
                    new X509EncodedKeySpec(publicKeyEncoding);
            publicKey =
                    (DHPublicKey)kf.generatePublic(x509KeySpec);
        } catch (Exception ex) {
            Logger.getLogger(DH.class.getName()).log(Level.SEVERE, null, ex);
            if (!failedPublicKeyGen) {
                failedPublicKeyGen = true;
                generatePublicKey();
            } else {
                throw ex;
            }
        }
    }

    private void generatePublicKeyEncoding() {
        publicKeyEncoding = null;
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ALGORITHM);

            keyGen.initialize(dhSpec);
            KeyPair kp = keyGen.generateKeyPair();

            ka = KeyAgreement.getInstance(ALGORITHM);
            ka.init(kp.getPrivate());

            publicKeyEncoding = kp.getPublic().getEncoded();
        } catch (Exception ex) {
            Logger.getLogger(DH.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

}
