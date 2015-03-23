package com.rsa.test.rsatest;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/**
 * Created by Administrator on 2015/3/23.
 */
public class RSA
{
    public static KeyPair generateKeyPair()
    {
        KeyPairGenerator keyGenerator = null;
        KeyPair keypair = null;
        try {
            keyGenerator = KeyPairGenerator.getInstance("RSA", "BC");
            SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
            keyGenerator.initialize(1024, random);
            keypair = keyGenerator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        }

        return keypair;
    }

    public static RSAPublicKey getPublicKey(BigInteger modulus, BigInteger publicExponent)
    {
        RSAPublicKey publicKey = null;
        try {
            publicKey = (RSAPublicKey) KeyFactory.getInstance("RSA", "BC").generatePublic(new RSAPublicKeySpec(modulus, publicExponent));
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        }

        return publicKey;
    }

    public static RSAPrivateKey getPrivateKey(BigInteger modulus, BigInteger privateExponent)
    {
        RSAPrivateKey privateKey = null;
        try {
            privateKey = (RSAPrivateKey) KeyFactory.getInstance("RSA", "BC").generatePrivate(new RSAPrivateKeySpec(modulus, privateExponent));
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        }
        return privateKey;
    }

    public static byte[] encrypt(String m, PublicKey publicKey)
    {
        byte[] encrypted = null;
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            encrypted = cipher.doFinal(m.getBytes());
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        }
        return encrypted;
    }

    public static byte[] decrypt(byte[] encrypted, PrivateKey privateKey)
    {
        byte[] decrypted = null;
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            decrypted = cipher.doFinal(encrypted);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
        return decrypted;
    }

    public static byte[] sign(String m,PrivateKey privateKey)
    {
        byte[] signed = null;
        try {
            Signature signature = Signature.getInstance("SHA1WITHRSA", "BC");
            signature.initSign(privateKey);
            signature.update(m.getBytes());
            signed = signature.sign();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        }
        return signed;
    }

    public static boolean verify(String m, byte[] sign, PublicKey publicKey)
    {
        boolean verify = false;
        try {
            Signature signature = Signature.getInstance("SHA1WITHRSA", "BC");
            signature.initVerify(publicKey);
            signature.update(m.getBytes());
            verify = signature.verify(sign);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        }
        return verify;
    }
}
