package crypto;

import java.io.*;
import java.net.*;
import java.security.*;
import java.util.Base64;
import java.util.HashSet;
import java.util.Set;

public class VA {
    private static final Set<String> tokenDump = new HashSet<>();

    public static void main(String[] args) throws Exception {
        ServerSocket serverSocket = new ServerSocket(5002);
        System.out.println("VA started. Waiting for voters...");
        
        PrivateKey vaPrivateKey = KeyManager.getPrivateKey("VA");
        PublicKey vaPublicKey = KeyManager.getPublicKey("VA");

        while (true) {
            Socket socket = serverSocket.accept();
            new Thread(new VAHandler(socket, vaPrivateKey, vaPublicKey)).start();
        }
    }

    public static Set<String> getTokenDump() {
        return tokenDump;
    }
}


class VAHandler implements Runnable {
	private final Socket socket;
	private final PrivateKey vaPrivateKey;
	private final PublicKey vaPublicKey;
	
	public VAHandler(Socket socket, PrivateKey vaPrivateKey, PublicKey vaPublicKey) {
		this.socket = socket;
		this.vaPrivateKey = vaPrivateKey;
		this.vaPublicKey = vaPublicKey;
	}
	
	public void run() {
		try (
			ObjectInputStream in = new ObjectInputStream(socket.getInputStream())
		) {
			byte[] encryptedVote = (byte[]) in.readObject();
            byte[] signedHashVote = (byte[]) in.readObject();
            byte[] signedToken = (byte[]) in.readObject();
            PublicKey voterPublicKey = (PublicKey) in.readObject();
            
            String vote = CryptoUtils.decrypt(encryptedVote, vaPrivateKey);
            // System.out.println("Decrypted vote: " + vote);
            
            String hashVote = CryptoUtils.hash(vote);
            boolean isVoteValid = CryptoUtils.verify(hashVote, signedHashVote, voterPublicKey);
            if (!isVoteValid) {
                System.out.println("Invalid vote signature! Vote rejected.");
                socket.close();
                return;
            }
            
            String token = new String(CryptoUtils.decryptWithPublicKey(signedToken, voterPublicKey)); 
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
            
            sendToBB(hashVote);
            System.out.println("Sent to BB.");
            
            byte[] signedHash = CryptoUtils.sign(hashVote, vaPrivateKey);
            sendToVS(signedHash);
            
            VA.getTokenDump().add(token);
            socket.close();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	private void sendToBB(String hashVote) throws Exception {
		PublicKey bbPublicKey = KeyManager.getPublicKey("BB");
		if (bbPublicKey == null) {
			throw new RuntimeException("BB public key not found in KeyManager.");
		}
		
		byte[] encryptedHash = CryptoUtils.encrypt(hashVote, bbPublicKey);
		
		try (Socket bb = new Socket("localhost", 5003);
				ObjectOutputStream out = new ObjectOutputStream(bb.getOutputStream())) {
			out.writeObject(encryptedHash);
			out.flush();
		}
    }
	
	private void sendToVS(byte[] signedHash) throws IOException {
		
	    try (Socket vs = new Socket("localhost", 5004);
	         ObjectOutputStream out = new ObjectOutputStream(vs.getOutputStream())) {
	        out.writeObject(signedHash);
	        out.flush();
	        System.out.println("Sent to VS.");
	    }
	}
	
}



