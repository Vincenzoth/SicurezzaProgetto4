package test;

import java.io.File;
import java.io.IOException;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;

import progetto4.DistribStorageException;
import progetto4.SecretSharingException;
import progetto4.SecureDistributedStorage;

public class testStorage {
	final static String BASE_PATH = Paths.get(System.getProperty("user.dir")).toString();
	final static String FILE_TO_TEST = "test.pdf";
	final static String FILE_EX_PATH = BASE_PATH + "/data/" + FILE_TO_TEST;
	final static String FILE_CLIENT_PATH = BASE_PATH + "/data/client/" + FILE_TO_TEST + ".sc";
	
	public static void main(String[] args) {
		SecureDistributedStorage secStor = new SecureDistributedStorage();
		
		File file = new File(FILE_EX_PATH);
		ArrayList<String> serverList = new ArrayList<String>();
		serverList.add("server1");
		serverList.add("server2");
		serverList.add("server3");
		serverList.add("server4");
		serverList.add("server5");
		
/*
		try {
			secStor.store(file, 3, 5, serverList);
		} catch (IOException | SecretSharingException | NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		*/
		
		
		try {
			secStor.load(FILE_CLIENT_PATH);
		} catch (IOException | DistribStorageException e) {
			e.printStackTrace();
		}
	}
	
}
