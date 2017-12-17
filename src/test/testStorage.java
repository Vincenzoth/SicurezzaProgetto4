package test;

import java.io.File;
import java.io.IOException;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;

import progetto4.DistribStorageException;
import progetto4.SecretSharingException;
import progetto4.SecureDistributedStorage;

public class testStorage {

	final static String MAC_ALG = "HmacSHA256";

	final static String BASE_PATH = Paths.get(System.getProperty("user.dir")).toString();
	//final static String FILE_TO_TEST = "testo.pdf";
	final static String FILE_TO_TEST = "fileEx";
	final static String FILE_EX_PATH = BASE_PATH + "/data/" + FILE_TO_TEST;
	final static String FILE_CLIENT_PATH = BASE_PATH + "/data/client/" + FILE_TO_TEST + ".sc";

	public static void main(String[] args) {
		String macKey = "chiaveDelMac";
		SecureDistributedStorage secStor = new SecureDistributedStorage();

		File file = new File(FILE_EX_PATH);
		ArrayList<String> serverList = new ArrayList<String>();
		serverList.add("server1");
		serverList.add("server2");
		serverList.add("server3");
		serverList.add("server4");
		serverList.add("server5");
		
		
		try {
			System.out.println(" ----- Generazione informazioni parziali ------------------------------ ");
			secStor.store(file, 3, 5, serverList, MAC_ALG, macKey);
		} catch (IOException | SecretSharingException | NoSuchAlgorithmException | InvalidKeyException e) {
			e.printStackTrace();
		}
		
		 

/*		
		//ricostruzione con in primi k server disponibili
		try {
		System.out.println(" ----- Ricostruzione file originale ----------------------------------- ");
			secStor.load(FILE_CLIENT_PATH, macKey, MAC_ALG);
			System.out.println();
			System.out.println("File ricostruito");
		} catch (IOException | DistribStorageException | InvalidKeyException | IllegalStateException | NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
	*/	 

		/*
		//selezione dei server da utilizzare per la ricostruzione
		try {
			System.out.println(" ----- Ricostruzione file originale ----------------------------------- ");
			String[] idEntrance = {"1", "5"};
			secStor.load(FILE_CLIENT_PATH, idEntrance, macKey, MAC_ALG);
			System.out.println();
			System.out.println("File ricostruito");
		} catch (IOException | DistribStorageException | InvalidKeyException | IllegalStateException | NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		*/


	}

}
