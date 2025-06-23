package crypto;

import java.io.*;
import java.net.*;
import java.security.*;

public class RA {

	private static KeyPair raKeyPair;
	
	static {
		try {
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
			keyGen.initialize(2048);
			raKeyPair = keyGen.generateKeyPair();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	public static void main(String[] args) throws IOException {
		ServerSocket serverSocket = new ServerSocket(5001);
		System.out.println("RA started. Waiting for voters...");
		
		while (true) {
			Socket clientSocket = serverSocket.accept();
			new Thread(new RAHandler(clientSocket, raKeyPair.getPrivate())).start();
		}
	}

}

class RAHandler implements Runnable {
    private Socket socket;
    private PrivateKey raPrivateKey;

    public RAHandler(Socket socket, PrivateKey raPrivateKey) {
        this.socket = socket;
        this.raPrivateKey = raPrivateKey;
    }

    public void run() {
        try (
            ObjectInputStream in = new ObjectInputStream(socket.getInputStream());
            ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream())
        ) {
            byte[] encryptedID = (byte[]) in.readObject();
            PublicKey voterPublicKey = (PublicKey) in.readObject();

            String voterID = CryptoUtils.decrypt(encryptedID, raPrivateKey);
            System.out.println("RA received ID: " + voterID);

            String token = CryptoUtils.hash(voterID);

            byte[] encryptedToken = CryptoUtils.encrypt(token, voterPublicKey);

            out.writeObject(encryptedToken);
            out.flush();

            System.out.println("RA sent encrypted token to voter.");
            socket.close();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
