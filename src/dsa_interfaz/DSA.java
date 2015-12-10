/*
 * Implementación del algoritmo de cifrado DSA
 */
package dsa_interfaz;

/**
 *
 * @author Ivan Garcia y Alvaro Alonso
 */
import java.math.BigInteger;
import java.util.Random;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;
import java.util.logging.Logger;

//Clase DSA
public class DSA {
    //Inicializacion de constantes
    //Tamaño del P
    private int TAMP=1024;
    //tamaño del Q
    private int TAMQ=160;
    //tolerancia de error del numero primo
    private int tolerancia = 10;
    
    private BigInteger q;
    private BigInteger p;
    private BigInteger g;
    private BigInteger y;
    private BigInteger x;
    private BigInteger k;

    //Constructor de la clase
    public DSA() {
    BigInteger q=null;
    BigInteger p=null;
    BigInteger g=null;
    BigInteger y=null;
    BigInteger x=null;
    BigInteger k=null;
    }

    //metodo encargado de generar la clave privada
    public BigInteger generarClave() {
        //Buscamos un numero P y Q
        q = new BigInteger(TAMQ, tolerancia, new Random());
        p = generaP(q, 1024);
        g = generaG(p, q);
        do {
            x = new BigInteger(q.bitCount(), new Random());
        } while (x.compareTo(BigInteger.ZERO) != 1 && x.compareTo(q) != -1);
        y = g.modPow(x, p);
        return y;
    }

    //metodo encargado de generar el numero P a partir de un numero Q y una longitud L
    private BigInteger generaP(BigInteger q, int l) {
        if (l % 64 != 0) {
            throw new IllegalArgumentException("El valor L no es correcto");
        }
        BigInteger pTemp;
        BigInteger pTemp2;
        do {
            pTemp = new BigInteger(l, tolerancia, new Random());
            pTemp2 = pTemp.subtract(BigInteger.ONE);
            pTemp = pTemp.subtract(pTemp2.remainder(q));
        } while (!pTemp.isProbablePrime(tolerancia) || pTemp.bitLength() != l);
        return pTemp;
    }

    //metodo encargado de generar el numero G a partir de P y Q
    private BigInteger generaG(BigInteger p, BigInteger q) {
        BigInteger aux = p.subtract(BigInteger.ONE);
        BigInteger pow = aux.divide(q);
        BigInteger gTemp;
        do {
            gTemp = new BigInteger(aux.bitLength(), new Random());
        } while (gTemp.compareTo(aux) != -1 && gTemp.compareTo(BigInteger.ONE) != 1);
        return gTemp.modPow(pow, p);
    }

    //metodo encargado de generar la rubrica
    public BigInteger generaRubrica() {
        k = generaK(q);
        BigInteger r = g.modPow(k, p).mod(q);
        return r;
    }

    //metodo encargado de generar la K
    public BigInteger generaK(BigInteger q) {
        BigInteger tempK;
        do {
            tempK = new BigInteger(q.bitLength(), new Random());
        } while (tempK.compareTo(q) != -1 && tempK.compareTo(BigInteger.ZERO) != 1);
        return tempK;
    }

    //metodo encargado de firmar el mensaje
    public BigInteger firmar(BigInteger r, byte[] data) {
        // Se genera un hash SHA-1 del mensaje y se firma
        MessageDigest md;
        BigInteger s = BigInteger.ONE;
        try {
            md = MessageDigest.getInstance("SHA-1");
            md.update(data);
            BigInteger hash = new BigInteger(md.digest());
            //Se realiza la firma
            s = (k.modInverse(q).multiply(hash.add(x.multiply(r)))).mod(q);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(DSA.class.getName()).log(Level.SEVERE, null, ex);
        }
        return s;
    }
    
    //metodo encargado de comprobar la firma con la rubrica
    boolean verifica(byte[] data, BigInteger r, BigInteger s) {
        if (r.compareTo(BigInteger.ZERO) <= 0 || r.compareTo(q) >= 0) {
            return false;
        }
        if (s.compareTo(BigInteger.ZERO) <= 0 || s.compareTo(q) >= 0) {
            return false;
        }
        MessageDigest md;
        BigInteger v = BigInteger.ZERO;
        try {
            //Calculamos el hash sha-1 del mensaje
            md = MessageDigest.getInstance("SHA-1");
            md.update(data);
            BigInteger hash = new BigInteger(md.digest());
            //Comprobamos que es correcto
            BigInteger w = s.modInverse(q);
            BigInteger u1 = hash.multiply(w).mod(q);
            BigInteger u2 = r.multiply(w).mod(q);
            v = ((g.modPow(u1, p).multiply(y.modPow(u2, p))).mod(p)).mod(q);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(DSA.class.getName()).log(Level.SEVERE, null, ex);
        }
        return v.compareTo(r) == 0;
    }

}
