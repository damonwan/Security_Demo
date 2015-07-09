package com.hangsheng.activemq.mqtt;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class Test {

	public static void main(String[] args) {
		try{
			KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA");
			
			keygen.initialize(1024);//1024位秘钥长度
			//生成keypair1
			KeyPair kpa = keygen.generateKeyPair();
			//生成keypair2
			KeyPair kpb = keygen.generateKeyPair();
			
			//双方通过网络交换公钥，即A的公钥传给B,B的公钥传给A
			
			//由一方生成会话秘钥(用于des,aes等加密算法)
			byte[] sessionkey = "我是".getBytes("utf-8");//对称秘钥
			//秘钥加上自己的数字签名，这样可以让对端进行验证，实现不可抵赖
			Signature sg = Signature.getInstance("MD5withRSA");
			sg.initSign(kpa.getPrivate());
			sg.update(sessionkey);
			byte[] signbytes = sg.sign();
			
			
			Cipher cipher = Cipher.getInstance("RSA");
			//A使用对方的公钥加密会话秘钥
			cipher.init(Cipher.ENCRYPT_MODE, kpb.getPublic());
			
			//使用公钥加密
		    
			
			byte[] encryBytes = cipher.doFinal(sessionkey);
			//B使用自己的私钥解密
			Cipher  deccipher = Cipher.getInstance("RSA");
			deccipher.init(Cipher.DECRYPT_MODE, kpb.getPrivate());
			byte[] decrybytes = deccipher.doFinal(encryBytes);
			
			System.out.println("解密后的对称秘钥是:"+new String(decrybytes,"utf-8"));
			
			//验证签名是否正确		
			Signature sg1 = Signature.getInstance("MD5withRSA");
			sg1.initVerify(kpa.getPublic());
			sg1.update(decrybytes);
			boolean bValid = sg1.verify(signbytes);
		    System.out.println("数字签名验证结果是:"+bValid);	
		    
		    //以下演示如何从公钥/私钥得到bytes,以及如何从bytes得到公钥/私钥
		    byte[] privatgeencoded = kpa.getPrivate().getEncoded();
		    byte[] publicencoded = kpa.getPublic().getEncoded();
		    
		    String privateformat = kpa.getPrivate().getFormat();//PKCS#8
		    System.out.println("private key format is :" + privateformat);
		    String publicformat = kpa.getPublic().getFormat();//X.509
		    System.out.println("public key format is :" + publicformat);
		    
		    java.security.spec.PKCS8EncodedKeySpec specprivate = new java.security.spec.PKCS8EncodedKeySpec(privatgeencoded);
		    java.security.spec.X509EncodedKeySpec x509public = new java.security.spec.X509EncodedKeySpec(publicencoded);
		    
		    KeyFactory kf = KeyFactory.getInstance("RSA");
		    PrivateKey privatekey = kf.generatePrivate(specprivate);
		    PublicKey publickey = kf.generatePublic(x509public);
		    
		    
		    //DES会话秘钥生成及恢复
		    String algorithm = "DES";
		    KeyGenerator kg = KeyGenerator.getInstance(algorithm);
		    SecretKey sk = kg.generateKey();
		    String skformat = sk.getFormat();
		    System.out.println("secret key format :"+skformat);
		    byte[] secretkeybytes = sk.getEncoded();
		    //从字节流恢复秘钥
		    SecretKeySpec sks = new SecretKeySpec(secretkeybytes,algorithm);
		    //加密
		    Cipher c1 = Cipher.getInstance(algorithm);
		    c1.init(Cipher.ENCRYPT_MODE, sk);
		    byte[] encmessage = c1.doFinal("这是DES加密算法原始字符串dsfdflkdsfdsfs还是原来的么".getBytes("utf-8"));
		    //解密
		    Cipher c2 = Cipher.getInstance(algorithm);
		    c2.init(Cipher.DECRYPT_MODE, sks);
		    byte[] orimessage = c2.doFinal(encmessage);
		    
		    System.out.println("原始DES消息是:"+new String(orimessage,"utf-8"));
		    
		    //AES会话秘钥生成及恢复
		    algorithm = "AES";
		    KeyGenerator kgaes = KeyGenerator.getInstance(algorithm);
		  
		    SecretKey aessk = kgaes.generateKey();
		    skformat = aessk.getFormat();
		    System.out.println("secret key format of aes is :"+skformat);
		    secretkeybytes = aessk.getEncoded();
		    //从字节流恢复秘钥
		    sks = new SecretKeySpec(secretkeybytes,algorithm);
		    //加密
		    Cipher c3 = Cipher.getInstance(algorithm);
		    c3.init(Cipher.ENCRYPT_MODE, aessk);
		    encmessage = c3.doFinal("这是AES加密算法原始字符串".getBytes("utf-8"));
		    
		    //解密
		    Cipher c4 = Cipher.getInstance(algorithm);
		    c4.init(Cipher.DECRYPT_MODE, sks);
		    orimessage = c4.doFinal(encmessage);
		    System.out.println("原始AES消息是:"+new String(orimessage,"utf-8"));
		    
		    
		    //RC4
		    algorithm = "RC4";
		    KeyGenerator kgrc4 = KeyGenerator.getInstance(algorithm);
		  
		    SecretKey rc4sk = kgrc4.generateKey();
		    skformat = rc4sk.getFormat();
		    System.out.println("secret key format of rc4 is :"+skformat);
		    secretkeybytes = rc4sk.getEncoded();
		    //从字节流恢复秘钥
		    sks = new SecretKeySpec(secretkeybytes,algorithm);
		    //加密
		    Cipher c5 = Cipher.getInstance(algorithm);
		    c5.init(Cipher.ENCRYPT_MODE, rc4sk);
		    encmessage = c5.doFinal("这是RC4加密算法原始字符串".getBytes("utf-8"));
		    
		    //解密
		    Cipher c6 = Cipher.getInstance(algorithm);
		    c6.init(Cipher.DECRYPT_MODE, sks);
		    orimessage = c6.doFinal(encmessage);
		    System.out.println("原始RC4消息是:"+new String(orimessage,"utf-8"));
			
		}catch(Exception ex){
			ex.printStackTrace();
		}
	}
}
