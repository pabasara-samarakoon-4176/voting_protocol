package crypto;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.util.Base64;

public class MultiVoterLauncher {
    public static void main(String[] args) {
        try {
            PublicKey raPublicKey = KeyManager.getPublicKey("RA");
            System.out.println("Voter using RA Public Key: " +
            	    CryptoUtils.hash(Base64.getEncoder().encodeToString(raPublicKey.getEncoded())));
            PublicKey vaPublicKey = KeyManager.getPublicKey("VA");

            for (int i = 1; i <= 10; i++) {
                final String voterID = "Voter" + i;

                KeyPair voterKeyPair = KeyManager.getKeyPair(voterID);
                if (voterKeyPair == null) {
                    voterKeyPair = KeyManager.generateAndStoreKeyPair("Voter" + i);
                }

                final KeyPair finalVoterKeyPair = voterKeyPair;

                new Thread(() -> {
                    try {
                        Voter.sendVote(voterID, finalVoterKeyPair, raPublicKey, vaPublicKey);
                    } catch (Exception e) {
                        System.err.println(voterID + " failed: " + e.getMessage());
                        e.printStackTrace();
                    }
                }).start();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
