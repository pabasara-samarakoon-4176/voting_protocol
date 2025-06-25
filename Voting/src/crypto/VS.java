package crypto;

import java.io.*;
import java.net.*;
import java.security.*;
import java.util.*;

public class VS {
	private static PrivateKey vsPrivateKey;
	private static PublicKey vaPublicKey;
	
	private static final Map<String, Integer> voteCount = new HashMap<>();
	private static final Map<String, String> choiceHashTable = new HashMap<>();
	
	static {
		try {
			vsPrivateKey = KeyManager.getPrivateKey("VS");
			vaPublicKey = KeyManager.getPublicKey("VA");

			if (vsPrivateKey == null || vaPublicKey == null) {
				throw new IllegalStateException("VS or VA keys not found in KeyManager.");
			}
			
			String c1 = "Yes";
			String c2 = "No";
			
			choiceHashTable.put(c1, CryptoUtils.hash(c1));
			choiceHashTable.put(c2, CryptoUtils.hash(c2));
			
			voteCount.put("Yes", 0);
			voteCount.put("No", 0);
		} catch (Exception e) {
			System.err.println("VS key initialization failed:");
			e.printStackTrace();
		}
	}
	
	public static void main(String[] args) throws IOException {
		ServerSocket vsSocket = new ServerSocket(5004);
        System.out.println("VS started. Waiting for VA...");

        while (true) {
            Socket va = vsSocket.accept();
            new Thread(new VSHandler(va, vsPrivateKey, vaPublicKey)).start();
        }

	}
	
	public static synchronized void tallyVote(String choice) {
		voteCount.put(choice,  voteCount.getOrDefault(choice, 0) + 1);
		System.out.println("Updated Tally:");
		voteCount.forEach((k, v) -> System.out.println(" " + k + ": " + v));
	}
	
	public static Map<String, String> getChoiceHashTable() {
		return choiceHashTable;
	}

}

class VSHandler implements Runnable {
	private final Socket socket;
	private final PrivateKey vsPrivateKey;
	private final PublicKey vaPublicKey;
	
	public VSHandler(Socket socket, PrivateKey vsPrivateKey, PublicKey vaPublicKey) {
		this.socket = socket;
		this.vsPrivateKey = vsPrivateKey;
		this.vaPublicKey = vaPublicKey;
	}
	
	public void run() {
		try (
			ObjectInputStream in = new ObjectInputStream(socket.getInputStream())
		) {
			byte[] signedHash = (byte[]) in.readObject();
			
			boolean matched = false;
			for (Map.Entry<String, String> entry : VS.getChoiceHashTable().entrySet()) {
                String choice = entry.getKey();
                String expectedHash = entry.getValue();

                if (CryptoUtils.verify(expectedHash, signedHash, vaPublicKey)) {
                    System.out.println("VS verified vote for choice: " + choice);
                    VS.tallyVote(choice);
                    matched = true;
                    break;
                }
            }
			
			if (!matched) {
                System.out.println("VS received invalid or unmatched vote hash.");
            }
			socket.close();
		} catch (Exception e) {
			System.out.println("VS error processing vote:");
            e.printStackTrace();
		}
	}
}
