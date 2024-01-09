package org.ua.rgr;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

import javax.crypto.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Base64;

/**
 * Unit test for simple App.
 */
public class AppTest 
    extends TestCase
{
    /**
     * Create the test case
     *
     * @param testName name of the test case
     */
    public AppTest( String testName )
    {
        super( testName );
    }

    /**
     * @return the suite of tests being tested
     */
    public static Test suite()
    {
        return new TestSuite( AppTest.class );
    }

    /**
     * Rigourous Test :-)
     */
    public void testApp() throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        SecretKey secretKey = KeyGenerator.getInstance("AES").generateKey();

        // Создание объекта шифрования
        Cipher cipher = Cipher.getInstance("AES");

        // Исходная строка, которую необходимо зашифровать
        String originalString = "0509;Kovalov Ivan;kovalevvana8@gmail.com";

        // Шифрование строки
        byte[] byteText = originalString.getBytes(StandardCharsets.UTF_8);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] byteCipherText = cipher.doFinal(byteText);

        // Преобразование зашифрованных данных в строку в формате Base64
        String encryptedString = Base64.getEncoder().encodeToString(byteCipherText);
        System.out.println("Зашифрованная строка: " + encryptedString);
        System.out.println(secretKey.getAlgorithm());
        System.out.println(secretKey.getFormat());

        byte[] encodedKey = secretKey.getEncoded();
        String encodedKeyString = Base64.getEncoder().encodeToString(encodedKey);
        System.out.println("Сгенерированный ключ: " + encodedKeyString);

    }

    public void testApp1() throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        // Генерация ключей RSA
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048); // Указываем размер ключа (в битах)
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        // Получение открытого и закрытого ключей
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        // Преобразование ключей в строки в формате Base64
        String publicKeyString = Base64.getEncoder().encodeToString(publicKey.getEncoded());
        String privateKeyString = Base64.getEncoder().encodeToString(privateKey.getEncoded());

        // Вывод ключей в консоль
        System.out.println("Открытый ключ (Public Key): " + publicKeyString);
        System.out.println("Закрытый ключ (Private Key): " + privateKeyString);

        // Шифрование строки с использованием открытого ключа
        String originalString = "0509;Kovalov Ivan;kovalevvana8@gmail.com";
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] byteCipherText = cipher.doFinal(originalString.getBytes());

        // Преобразование зашифрованных данных в строку в формате Base64
        String encryptedString = Base64.getEncoder().encodeToString(byteCipherText);
        System.out.println("Зашифрованная строка: " + encryptedString);

    }
}
