package crypto;

import java.io.*;
import java.net.*;

public class BB {

	public static void main(String[] args) throws IOException {
		ServerSocket bbSocket = new ServerSocket(5003);
        System.out.println("BB started. Waiting for VA...");

        while (true) {
            Socket va = bbSocket.accept();
            BufferedReader in = new BufferedReader(new InputStreamReader(va.getInputStream()));
            String hash = in.readLine();
            System.out.println("BB received hashed vote: " + hash);
            va.close();
        }

	}

}
