package progetto4;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Locale;

public class SecureDistributedStorage {
	public static final String BASE_PATH = Paths.get(System.getProperty("user.dir")).toString();
	public static final String FILE_EX_PATH = BASE_PATH + "/data/fileEx";
	public static final String SERVERS_PATH = BASE_PATH + "/data/servers/";
	public static final String CLIENT_PATH = BASE_PATH + "/data/client/";
	public static final String CLIENT_PATH_REC_FILE = BASE_PATH + "/data/client/recFiles/";

	public static final int LEN_BLOCK = 300;
	public static final int RANDOM_NAMEFILE_LEN = 15;
	public static final String HASH_ALG = "SHA-256";

	private static final String UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	private static final String LOWER = UPPER.toLowerCase(Locale.ROOT);
	private static final String DIGITS = "0123456789";
	private static final String ALPHANUM = UPPER + LOWER + DIGITS;

	private SecretSharing secShar;

	public SecureDistributedStorage() {
		secShar = new SecretSharing();

		File testPath = new File(SERVERS_PATH);
		if(!testPath.exists())		 
			testPath.mkdirs();

		testPath = new File(CLIENT_PATH);
		if(!testPath.exists())		 
			testPath.mkdirs();
	}

	/**
	 * Il metodo applica lo schema di Shamir e genera i file contenenti le informazioni parziali da memorizzare sui vari server.
	 * Il metodo inoltre genera le informazioni da conservare nel client per poter poi ricostruire il file originale
	 * @param fileToStore
	 * @param k
	 * @param n
	 * @param serverList
	 * @throws IOException
	 * @throws SecretSharingException
	 * @throws NoSuchAlgorithmException
	 */
	public void store(File fileToStore, int k, int n, ArrayList<String> serverList) throws IOException, SecretSharingException, NoSuchAlgorithmException {
		ArrayList<Entrant> informations = new ArrayList<Entrant>();
		InputStream ios = null;

		// array ordinato dei nomi dei file che verranno generati
		ArrayList<String> fileNameList = generateFilesName(serverList);

		ios = new FileInputStream(fileToStore);
		BigInteger secret;
		BigInteger prime = null;
		long fileSize = fileToStore.length();
		int iter = 1;
		long remainingByte = fileSize;

		byte[] buffer;
		byte[] secretByte;

		if(remainingByte < LEN_BLOCK) {
			buffer = new byte[(int) remainingByte];
			secretByte = new byte[(int) (remainingByte + 1)];
		}else {
			buffer = new byte[LEN_BLOCK];
			secretByte = new byte[LEN_BLOCK + 1];
		}


		while ((ios.read(buffer)) != -1) {
			System.out.println("----Iter ----");
			System.out.println("Len: " + buffer.length);

			// la prima volta viene generato il primo, per gli altri blocchi si utilizza sempre lo stesso primo
			if(prime == null) {
				secretByte[0] = 10;
				System.arraycopy(buffer, 0, secretByte, 1, buffer.length);
				secret = new BigInteger(secretByte);
				System.out.println(Arrays.toString(secretByte));
				System.out.println("BigInteger: " + secret);

				secShar.setSecret(secret);

				prime = secShar.generatePartialInformations(k, n, informations);
			}else {
				secretByte[0] = 1;
				System.arraycopy(buffer, 0, secretByte, 1, buffer.length);
				secret = new BigInteger(secretByte);
				System.out.println(Arrays.toString(secretByte));
				System.out.println("BigInteger: " + secret);

				secShar.setSecret(secret);

				secShar.generatePartialInformations(k, n, prime, informations);
			}

			// write partial information to storage servers
			System.out.println(informations);
			storeToServers(informations, fileNameList, serverList);

			System.out.println();

			// write local informationto client
			storeClient(fileToStore, k, prime, fileNameList, serverList);

			remainingByte = fileSize - (iter * LEN_BLOCK);
			if(remainingByte < LEN_BLOCK && remainingByte > 0) {
				buffer = new byte[(int) remainingByte];
				secretByte = new byte[(int) (remainingByte + 1)];
			}			
			iter++;
		}
		ios.close();
	}

	/**
	 * Il metodo scrive le informazioni parziali nei server nell'ordine in cui sono presenti nella lista serverList
	 * @param partialInformations
	 * @param serverList
	 * @throws IOException 
	 * @throws DistribStorageException 
	 */

	public void load(String fileToLoad_path) throws IOException, DistribStorageException {
		File fileToLoad = new File(fileToLoad_path);

		// leggere le informazioni dal file
		BigInteger prime;
		int k;
		ArrayList<String> serverList = new ArrayList<String>();
		ArrayList<String> filesList = new ArrayList<String>();
		String hashOriginalFile;

		BufferedReader breader = new BufferedReader(new FileReader(fileToLoad));

		prime = new BigInteger(breader.readLine());
		k = Integer.parseInt(breader.readLine());

		String serverListString = breader.readLine();
		serverListString = serverListString.substring(1, serverListString.length()-1);
		for(String server: serverListString.split(", ")) {
			serverList.add(server);
		}

		String filesListString = breader.readLine();
		filesListString = filesListString.substring(1, filesListString.length()-1);
		for(String file: filesListString.split(", ")) {
			filesList.add(file);
		}

		hashOriginalFile = breader.readLine();		

		breader.close();		


		// ottenere le k informazioni dai server
		// consiedriamo le prime k informazioni reperibili
		File[] partialInfoFiles = new File[k];
		String[] idsEntrance = new String[k];

		getPartialInformationFiles(k, serverList, filesList, partialInfoFiles, idsEntrance);

		obtainOriginalFile(idsEntrance, partialInfoFiles);

		//secShar.computeSecret(partialInformations)

	}

	private void storeToServers(ArrayList<Entrant> partialInformations, ArrayList<String> filesName, ArrayList<String> serverList) throws IOException {
		int i = 0;
		byte[] byteSecret;
		FileOutputStream out = null;
		for(Entrant e: partialInformations) {

			File pathServer = new File(SERVERS_PATH + serverList.get(i) + "/");
			if(!pathServer.exists()) { 			 
				pathServer.mkdirs();
			}

			byteSecret = e.getS_i().toByteArray();

			out = new FileOutputStream(SERVERS_PATH + serverList.get(i) + "/" + filesName.get(i), true);
			out.write(byteSecret);
			out.flush();

			System.out.println("    len inf: " + byteSecret.length + "    Store to: " + serverList.get(i));
			i++;
		}
		out.close();
	}

	/**
	 * Il metodo genera in maniera casuale i nomi che verranno assegnati ai file delle informazioni parziali memorizzati sui vari server.
	 * @param serverList  -  lista dei server interessati
	 * @return     -  Una lista di nomi casuali per i file da generare
	 */
	private ArrayList<String> generateFilesName(ArrayList<String> serverList){
		ArrayList<String> nameFile = new ArrayList<String>();
		String ranName;
		for(String server: serverList) {
			do {
				ranName = randomName();
			}while(!fileNotInServer(ranName, server));

			nameFile.add(ranName);
		}

		return nameFile;
	}

	/**
	 * Genera e restituisce una stringa a caso di lunghezza RANDOM_NAMEFILE_LEN
	 * @return la stringagenerata a casa
	 */
	private String randomName() {
		char[] symbols = ALPHANUM.toCharArray();
		SecureRandom random = new SecureRandom();
		char[] buf = new char[RANDOM_NAMEFILE_LEN];

		for (int i = 0; i < buf.length; ++i)
			buf[i] = symbols[random.nextInt(symbols.length)];

		return new String(buf);
	}

	/**
	 * Il metodo verifica se nel server è gia presente un file con nome nameFile
	 * @param nameFile  - nome file da testare
	 * @param server    - nome server
	 * @return          - true se non esiste gia un file con nome nameFile, false altrimenti
	 */
	private boolean fileNotInServer(String nameFile, String server) {
		File file = new File(SERVERS_PATH + server + "/" + nameFile);

		return file.exists() ? false:true;
	}

	/**
	 * Il metodo genera le informazioni da conservare sul client
	 * @param fileToStore
	 * @param k
	 * @param prime
	 * @param fileNameList
	 * @param serverList
	 * @throws IOException 
	 * @throws NoSuchAlgorithmException 
	 */
	private void storeClient(File fileToStore, int k, BigInteger prime, ArrayList<String> fileNameList, ArrayList<String> serverList) throws IOException, NoSuchAlgorithmException {		
		MessageDigest md = MessageDigest.getInstance(HASH_ALG);
		byte[] inputBytes = Files.readAllBytes(Paths.get(fileToStore.getPath()));
		md.update(inputBytes);
		byte[] hashedBytes = md.digest();

		PrintWriter writer =  new PrintWriter(CLIENT_PATH + fileToStore.getName() + ".sc");

		writer.println(prime);
		writer.println(k);
		writer.println(serverList);
		writer.println(fileNameList);
		writer.println(byteArrayToHexString(hashedBytes));

		writer.close();		
	}

	/**
	 * Il metodo recupera dai server i primi k file contenenti le informazioni parziali disponibili.
	 * 
	 * @param k
	 * @param serverList
	 * @param fileList
	 * @return  -  Una lista di file conteneti i file delle informazioni parziali
	 * @throws DistribStorageException
	 */
	private void getPartialInformationFiles(int k, ArrayList<String> serverList, ArrayList<String> fileList, File[] partialInfoFiles, String[] idsEntrance) throws DistribStorageException{		
		String pathFile;
		File testFile;
		int foundedFile = 0;
		int i = 0;

		while(foundedFile < k && i < serverList.size()) {
			pathFile = SERVERS_PATH + serverList.get(i) + File.separator + fileList.get(i);
			testFile = new File(pathFile);

			if(testFile.exists()) {
				partialInfoFiles[foundedFile] = testFile;
				idsEntrance[foundedFile] = Integer.toString(i+1);
				foundedFile++;
			}
			i++;
		}

		if(foundedFile < k)
			throw new DistribStorageException("Non sono disponilibi abbastanza server. Server disponibili " + foundedFile);

	}

	private void obtainOriginalFile(String[] idsEntrance, File[] partialInfoFiles) {
		//CLIENT_PATH_REC_FILE
		
		ArrayList<Entrant> informations = new ArrayList<Entrant>();
		InputStream ios = null;

	}

	private String byteArrayToHexString(byte[] arrayBytes) {
		StringBuffer stringBuffer = new StringBuffer();
		for (int i = 0; i < arrayBytes.length; i++) {
			stringBuffer.append(Integer.toString((arrayBytes[i] & 0xff) + 0x100, 16)
					.substring(1));
		}
		return stringBuffer.toString();
	}

	private byte[] hexStringToByteArray(String s) {
		int len = s.length();
		byte[] data = new byte[len / 2];
		for (int i = 0; i < len; i += 2) {
			data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
					+ Character.digit(s.charAt(i+1), 16));
		}
		return data;
	}

}
