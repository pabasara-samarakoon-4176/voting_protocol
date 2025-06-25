package crypto;

import java.security.*;
import java.util.HashMap;
import java.util.Map;
import java.io.*;
import java.util.Base64;

public class KeyManager {
    private static final Map<String, KeyPair> keys = new HashMap<>();
    private static final String KEY_FOLDER = "keys";

    static {
        new File(KEY_FOLDER).mkdirs();
        loadKey("RA");
        loadKey("VA");
        loadKey("BB");
        loadKey("VS");
    }

    public static KeyPair getKeyPair(String name) {
        return keys.get(name);
    }

    public static PublicKey getPublicKey(String name) {
        KeyPair kp = keys.get(name);
        return kp != null ? kp.getPublic() : null;
    }

    public static PrivateKey getPrivateKey(String name) {
        KeyPair kp = keys.get(name);
        return kp != null ? kp.getPrivate() : null;
    }

    public static KeyPair generateAndStoreKeyPair(String name) {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            KeyPair kp = keyGen.generateKeyPair();
            saveKey(name, kp);
            keys.put(name, kp);
            return kp;
        } catch (Exception e) {
            throw new RuntimeException("Key generation failed for: " + name, e);
        }
    }
    
    private static void saveKey(String name, KeyPair kp) throws Exception {
        try (ObjectOutputStream out = new ObjectOutputStream(
                new FileOutputStream(KEY_FOLDER + "/" + name + ".key"))) {
            out.writeObject(kp);
        }
    }
    
    private static void loadKey(String name) {
        File file = new File(KEY_FOLDER + "/" + name + ".key");
        if (!file.exists()) {
            generateAndStoreKeyPair(name);
            return;
        }

        try (ObjectInputStream in = new ObjectInputStream(new FileInputStream(file))) {
            KeyPair kp = (KeyPair) in.readObject();
            keys.put(name, kp);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
}
