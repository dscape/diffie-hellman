package edu.pt.uminho.di.msc.cripto.csi.tests;

import edu.pt.uminho.di.msc.cripto.csi.*;
import javax.crypto.KeyAgreement;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import edu.pt.uminho.di.msc.cripto.util.Strings;

import static org.junit.Assert.*;

public class DHTest {

    public DHTest() {
    }

    @BeforeClass
    public static void setUpClass() throws Exception {
    }

    @AfterClass
    public static void tearDownClass() throws Exception {
    }

    @Before
    public void setUp() {
    }

    @After
    public void tearDown() {
    }

    @Test
    public void agreeOnKeysDefaultValuePG() {
        try {
            System.out.println("agreeOnKeysDefaultValuePG");
            DH alice = new DH(DH.USE_DEF_DH_PARAMS);
            assert(agreeOnKeys(alice));
        } catch (Exception ex) {
            fail("An Exception Occurred");
            ex.printStackTrace();
        }
    }
    
    @Test
    public void agreeOnKeysGeneratedPG() {
        try {
            System.out.println("agreeOnKeysGeneratedPG");
            DH alice = new DH(DH.GENERATE_DH_PARAMS);
            assert(agreeOnKeys(alice));
        } catch (Exception ex) {
            fail("An Exception Occurred");
            ex.printStackTrace();
        }
    }

    private boolean agreeOnKeys(DH alice) throws Exception {
        DH bob = new DH(alice.getDHPublicKey().getParams());

        KeyAgreement kab = bob.getDHKeyAgreement();
        KeyAgreement kaa = alice.getDHKeyAgreement();

        kaa.doPhase(bob.getDHPublicKey(), true);
        kab.doPhase(alice.getDHPublicKey(), true);

        return Strings.toHexString(kab.generateSecret()).equals(
                Strings.toHexString(kaa.generateSecret()));
    }
}
