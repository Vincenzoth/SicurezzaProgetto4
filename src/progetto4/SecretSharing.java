package progetto4;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Random;

public class SecretSharing {
	private final int CERTAINTY = 50;

	private BigInteger s;
	private int modLength;
	private BigInteger p;

	public SecretSharing() {
		//this.modLength = modLength; // calcolala dinamicamente
		this.s = null;
	}

	/**
	 * Il metodo imposta il segreto s
	 * @param s 
	 */
	public void setSecret(BigInteger s) {
		this.s = s;
		this.modLength = s.bitLength() + 1;
	}
	
	/**
	 * Il metodo imposta il primo p
	 * @param p
	 */
	public void setPrime(BigInteger p) {
		this.p = p;
		this.modLength = p.bitLength();
	}

	/**
	 * Il metodo genera le informazioni parziali per lo schema di Shamir.
	 * @param k  -  parametro k dello schema di Shamir, è il numero minimo di informazioni per poter ricostruire il segreto
	 * @param n  -  parametro n dello schema di Shamir, è il numero di informaizni parziali che verranno generate
	 * @param partialInformations  -  array nel quale verranno memorizzate le informazioni parziali generate
	 * @return  -  il primo generato sul quale si basa lo schema
	 * @throws SecretSharingException 
	 */
	public BigInteger generatePartialInformations(int k, int n, ArrayList<Entrant> partialInformations) throws SecretSharingException{
		if(s == null) 
			throw new SecretSharingException("Segreto non impostato!");
		
		if(!partialInformations.isEmpty())
			partialInformations.clear();

		// generazione di un primo p,  p>s & p>n
		this.p = null;
		do {
			p = genPrime();			
		}while(p.compareTo(this.s) <= 0 && p.compareTo(BigInteger.valueOf(n)) <= 0);

		generatePartialInformations_base(k, n, partialInformations);
				
		return this.p;
	}
	
	/**
	 * Il metodo genera le informazioni parziali per lo schema di Shamir.
	 * @param k  -  parametro k dello schema di Shamir, è il numero minimo di informazioni per poter ricostruire il segreto
	 * @param n  -  parametro n dello schema di Shamir, è il numero di informaizni parziali che verranno generate
	 * @param p  -  primo di rifrimento dello schema di Shamir
	 * @param partialInformations  -  array nel quale verranno memorizzate le informazioni parziali generate
	 * @throws SecretSharingException 
	 */
	public void generatePartialInformations(int k, int n, BigInteger p, ArrayList<Entrant> partialInformations) throws SecretSharingException{
		if(s.equals(null)) 
			throw new SecretSharingException("Segreto non impostato!");
		if(s.compareTo(p) >= 0)
			throw new SecretSharingException("Il primo p non è più grande del segreto s!");
		
		if(!partialInformations.isEmpty())
			partialInformations.clear();
		
		this.p = p;
		
		generatePartialInformations_base(k, n, partialInformations);
		
	}
	
	/**
	 * metodo di supporto per il calcolo delle informazioni parziali
	 * @param k  -  parametro k dello schema di Shamir, è il numero minimo di informazioni per poter ricostruire il segreto
	 * @param n  -  parametro n dello schema di Shamir, è il numero di informaizni parziali che verranno generate
	 * @param p  -  primo di rifrimento dello schema di Shamir
	 * @param partialInformations  -  array nel quale verranno memorizzate le informazioni parziali generate
	 */
	private void generatePartialInformations_base(int k, int n, ArrayList<Entrant> partialInformations) {
		BigInteger[] coeffs = new BigInteger[k-1]; // array dei coefficienti del polinomio di grado k-1

		// definizione del polinomio
		//   f(x) = s + a_1 x + a_2 x^2 + ... + a_k x^k
		for(int i = 0; i < k-1; i++){
			coeffs[i] = randomZp();
		}

		//definizione informazioni parziali
		BigInteger partialInfo_i;
		for(int i = 1; i <= n; i++) {
			partialInfo_i = this.s;
			for(int j = 1; j < k; j++) {
				partialInfo_i = partialInfo_i.add(coeffs[j-1].multiply(BigInteger.valueOf((int)Math.pow(i, j))));
			}	
			partialInfo_i = partialInfo_i.mod(p);
			partialInformations.add(new Entrant(Integer.toString(i), partialInfo_i));
		}
	}

	/**
	 * Il metodo ricostruisece e restituisce il segreto a partire dalla lista di informazioni parziali passata come parametro. 
	 * Utilizza l'intrpolazione di Lagrange per ricostruire il polinomio e valutare il segreto.
	 * @param partialInformations
	 * @return
	 */
	public BigInteger computeSecret(ArrayList<Entrant> partialInformations) {
		BigInteger secret = BigInteger.ZERO;
		BigInteger mulValue = BigInteger.ONE;
		BigInteger mulInv = BigInteger.ONE;

		for(Entrant u: partialInformations) {
			for(Entrant u_mul: partialInformations) {
				if(u.getId().compareTo(u_mul.getId()) != 0) {

					mulInv = u_mul.getId().subtract(u.getId()).modInverse(p);

					mulValue = mulValue.multiply(
							u_mul.getId().multiply(mulInv)
							);
				}
			}
			
			secret = secret.add(
					u.getS_i().multiply(mulValue.mod(p))
					);
			mulValue = BigInteger.ONE;
			mulInv = BigInteger.ONE;
		}

		secret = secret.mod(p);

		return secret;	
	}

	/**
	 * Il metodo genera e restituisce un numero primo
	 * @return un primo della calsse BigInteger
	 */
	private BigInteger genPrime() {
		BigInteger p = null;
		boolean ok = false;

		do {
			p = BigInteger.probablePrime(this.modLength, new Random());
			if(p.isProbablePrime(this.CERTAINTY))
				ok = true;
		}while(ok == false);

		return p;
	}

	/**
	 * Il metodo genera e restituisce un numero casuale in Zp
	 * @return un numero in Zp della calsse BigInteger
	 */
	private BigInteger randomZp() {
		BigInteger r;
		do {
			r = new BigInteger(this.modLength, new Random());
		}while(r.compareTo(BigInteger.ZERO) < 0 || r.compareTo(this.p) >= 0);

		return r;
	}
}

