package com.rsa;

import java.math.BigInteger;
import java.util.Random;
import java.util.StringTokenizer;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class Main {

    private static final Logger logger = LogManager.getLogger(Main.class);
    private static final String token = ";";

    public static void main(String[] args) {
        String inputFile = "dati/input.txt"; 
        String encryptedFile = "dati/DatiCriptato.txt";
        String decryptedFile = "dati/DatiDecriptato.txt";

        try {
            String data = readFromFile(inputFile);
            rsaEncrypt(data, encryptedFile, decryptedFile);
        } catch (IOException e) {
            logger.error("Errore nella lettura/scrittura del file: ", e);
        }
    }

    private static void rsaEncrypt(String data, String encryptedFile, String decryptedFile) throws IOException {
        try {
            logger.info("Generazione delle chiavi RSA...");
            Random rng = new Random();
            BigInteger firstPrime = BigInteger.probablePrime(128, rng);
            BigInteger secondPrime = BigInteger.probablePrime(128, rng);
            BigInteger n = firstPrime.multiply(secondPrime);
            BigInteger z = (firstPrime.subtract(BigInteger.ONE)).multiply(secondPrime.subtract(BigInteger.ONE));
            BigInteger e = BigInteger.valueOf(65537);
            if (!e.gcd(z).equals(BigInteger.ONE)) {
                e = coPrime(z);
            }
            BigInteger d = e.modInverse(z);
            logger.info("Prime: {}, SecondPrime: {}", firstPrime, secondPrime);
            logger.info("n: {}, z: {}, e: {}, d: {}", n, z, e, d);
            logger.info("Chiavi generate con successo.");

            logger.info("Cifratura del file: {}", encryptedFile);
            String encryptedData = encrypt(data, e, n);
            logger.info("Dati Cifrati: {}", encryptedData);
            writeToFile(encryptedFile, encryptedData);
            logger.info("File cifrato salvato in: {}", encryptedFile);

            logger.info("Decifratura del file: {}", encryptedFile);
            String decryptedData = decrypt(encryptedData, d, n);
            logger.info("Dati Decrittati: {}", decryptedData);
            writeToFile(decryptedFile, decryptedData);
            logger.info("File decifrato salvato in: {}", decryptedFile);
        } catch (IOException e) {
            logger.error("Errore durante la cifratura/decifratura: ", e);
            throw e;
        }
    }

    private static String encrypt(String data, BigInteger e, BigInteger n) {
        StringBuilder encrypted = new StringBuilder();
        for (char character : data.toCharArray()) {
            BigInteger m = BigInteger.valueOf(character);
            BigInteger c = m.modPow(e, n);
            encrypted.append(c).append(token);
        }
        return encrypted.toString();
    }

    private static String decrypt(String data, BigInteger d, BigInteger n) {
        StringTokenizer tokenizer = new StringTokenizer(data, token);
        StringBuilder decrypted = new StringBuilder();
        while (tokenizer.hasMoreTokens()) {
            String token = tokenizer.nextToken();
            if (!token.isEmpty()) {
                BigInteger c = new BigInteger(token);
                BigInteger m = c.modPow(d, n);
                decrypted.append((char) m.intValue());
            }
        }
        return decrypted.toString();
    }

    private static BigInteger coPrime(BigInteger z) {
        Random rng = new Random();
        BigInteger e;
        do {
            e = BigInteger.probablePrime(64, rng);
        } while (!e.gcd(z).equals(BigInteger.ONE));
        return e;
    }

    private static String readFromFile(String filePath) throws IOException {
        logger.debug("Lettura del file: {}", filePath);
        return new String(Files.readAllBytes(Paths.get(filePath)));
    }

    private static void writeToFile(String filePath, String data) throws IOException {
        logger.debug("Scrittura dei dati nel file: {}", filePath);
        Files.write(Paths.get(filePath), data.getBytes(), StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
    }
}
