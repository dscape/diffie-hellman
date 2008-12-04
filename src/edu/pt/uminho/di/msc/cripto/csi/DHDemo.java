package edu.pt.uminho.di.msc.cripto.csi;

import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.KeyAgreement;
import edu.pt.uminho.di.msc.cripto.util.Strings;

public class DHDemo {
    private static final String USAGE = "\nHow to use: ./DHDemo [-gen]";

    public static void main(String[] args) {
        if (args.length == 0) {
            runDHDemo(DH.USE_DEF_DH_PARAMS);
        } else if (args.length == 1 && args[0].equals("-gen")) {
            runDHDemo(DH.GENERATE_DH_PARAMS);
        } else {
            System.out.println(USAGE);
            return;
        }
    }
    
    public static void runDHDemo(int mode) {
        try {
            DH alice = new DH(mode);
            DH bob = new DH(alice.getDHPublicKey().getParams());

            KeyAgreement kab = bob.getDHKeyAgreement();
            KeyAgreement kaa = alice.getDHKeyAgreement();

            kaa.doPhase(bob.getDHPublicKey(), true);
            kab.doPhase(alice.getDHPublicKey(), true);

            if (Strings.toHexString(kab.generateSecret())
                    .equals(Strings.toHexString(kaa.generateSecret()))) {
                System.out.println("MATCH");
            }

        } catch (Exception e) {
            Logger.getLogger(DH.class.getName()).log(Level.WARNING, null, e);
        }
    }

}