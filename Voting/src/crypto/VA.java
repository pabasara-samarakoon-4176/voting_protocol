package crypto;

import java.io.*;
import java.net.*;
import java.security.*;
import java.util.Base64;
import java.util.HashSet;
import java.util.Set;

public class VA {
    private static KeyPair vaKeyPair;
    private static final Set<String> tokenDump = new HashSet<>();

    static {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            vaKeyPair = keyGen.generateKeyPair();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) throws Exception {
        ServerSocket serverSocket = new ServerSocket(5002);
        System.out.println("VA started. Waiting for voters...");

        while (true) {
            Socket socket = serverSocket.accept();
            new Thread(new VAHandler(socket, vaKeyPair)).start();
        }
    }

    public static Set<String> getTokenDump() {
        return tokenDump;
    }
}


class VAHandler implements Runnable {
	private final Socket socket;
	private final KeyPair vaKeyPair;
	
	public VAHandler(Socket socket, KeyPair vaKeyPair) {
		this.socket = socket;
		this.vaKeyPair = vaKeyPair;
	}
	
	public void run() {
		try (
			ObjectInputStream in = new ObjectInputStream(socket.getInputStream())
		) {
			byte[] encryptedVote = (byte[]) in.readObject();
            byte[] signedHashVote = (byte[]) in.readObject();
            byte[] signedToken = (byte[]) in.readObject();
            PublicKey voterPublicKey = (PublicKey) in.readObject();
            
            String vote = CryptoUtils.decrypt(encryptedVote, vaKeyPair.getPrivate());
            System.out.println("Decrypted vote: " + vote);
            
            String hashVote = CryptoUtils.hash(vote);
            boolean isVoteValid = CryptoUtils.verify(hashVote, signedHashVote, voterPublicKey);
            if (!isVoteValid) {
                System.out.println("Invalid vote signature! Vote rejected.");
                socket.close();
                return;
            }
            
            String token = new String(CryptoUtils.getSignedMessage(signedToken, voterPublicKey)); // or reconstruct from trust
            if (token == null || token.isBlank()) {
                System.out.println("Invalid token or signature. Vote rejected.");
                socket.close();
                return;
            }
            
            if (VA.getTokenDump().contains(token)) {
                System.out.println("Duplicate vote attempt! Token already used.");
                socket.close();
                return;
            }
            
            System.out.println("Vote accepted. Proceeding to BB and VS.");
            
            byte[] encryptedHash = CryptoUtils.encrypt(hashVote, getBBPublicKey()); // Replace with BB's actual key
            sendToBB(encryptedHash);
            
            byte[] signedHash = CryptoUtils.sign(hashVote, vaKeyPair.getPrivate());
            byte[] encryptedSignedHash = CryptoUtils.encryptBytes(signedHash, getVSPublicKey()); // Replace with VS's key
            sendToVS(encryptedSignedHash);
            
            VA.getTokenDump().add(token);
            socket.close();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	private void sendToBB(byte[] encryptedHash) throws IOException {
        Socket bb = new Socket("localhost", 5003); 
        ObjectOutputStream out = new ObjectOutputStream(bb.getOutputStream());
        out.writeObject(encryptedHash);
        out.flush();
        bb.close();
    }
	
	private void sendToVS(byte[] encryptedSignedHash) throws IOException {
        Socket vs = new Socket("localhost", 5004); 
        ObjectOutputStream out = new ObjectOutputStream(vs.getOutputStream());
        out.writeObject(encryptedSignedHash);
        out.flush();
        vs.close();
    }
	
	private PublicKey getBBPublicKey() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        return gen.generateKeyPair().getPublic();
    }
	
	private PublicKey getVSPublicKey() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        return gen.generateKeyPair().getPublic();
    }
}



