package progetto4;

import java.math.BigInteger;
/**
 * La classe rappresenta un partecipante nello schema di Shamir
 *
 */
public class Entrant {

	private BigInteger id;
	private BigInteger s_i;
	
	public Entrant(String id, BigInteger s_i) {
		this.id = new BigInteger(id);
		this.s_i = s_i;
	}

	public BigInteger getId() {
		return id;
	}

	public BigInteger getS_i() {
		return s_i;
	}

	public void setS_i(BigInteger s_i) {
		this.s_i = s_i;
	}
	
	public String toString() {
		return "<id:" + id +" ; s_i:" + s_i +">";
	}
	
}
