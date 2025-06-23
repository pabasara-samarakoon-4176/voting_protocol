package crypto;

public class MultiVoterLauncher {

	public static void main(String[] args) {
		for (int i = 1; i <= 3; i++) {
			final String voterID = "Voter" + i;
			new Thread(() -> {
				try {
					Voter.sendVote(voterID);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}).start();
		}

	}

}
