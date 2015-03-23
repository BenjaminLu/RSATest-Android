##Install
1. Import this project into [Android Studio](http://developer.android.com/sdk/index.html).
2. Change "server url" String in strings.xml of Android project to your ip or domain.
3. Download the server project from [this repository](https://github.com/BenjaminLu/RSATest-Server).
4. Import server project into [Eclipse EE](https://www.eclipse.org/downloads/packages/eclipse-ide-java-ee-developers/lunasr2).
5. Start Spring MVC server web project with [Tomcat 8](http://tomcat.apache.org/tomcat-8.0-doc/index.html).

##Test
1. Start the main activity of Android project.
2. press the "SEND" button & see the output in logcat.

##APIs
Generate RSA key pair
```java
KeyPair keyPair = RSA.generateKeyPair();
RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) keyPair.getPrivate();
RSAPublicKey rsaPublicKey = (RSAPublicKey) keyPair.getPublic();
```
Encryption & Decryption
```java
String m = "Your message";
byte[] encrypted = RSA.encrypt(m, rsaPublicKey);
byte[] decrypted = RSA.decrypt(encrypted, rsaPrivateKey);
```
Sign & Verify
```java
byte[] sign = RSA.sign(m, rsaPrivateKey);
String signBase64 = Base64.encode(sign);
String modulusString = rsaPublicKey.getModulus().toString();
String publicExponentString = rsaPublicKey.getPublicExponent().toString();
//Send message m, signBase64, modulusString and publicExponentString to counterparty.
byte[] sign = Base64.decode(signBase64, Base64.DEFAULT);
BigInteger modulus = new BigInteger(modulusString);
BigInteger publicExponent = new BigInteger(publicExponentString);
RSAPublicKey rsaPublicKey = RSA.getPublicKey(modulus, publicExponent);
boolean verify = RSA.verify(m, sign, rsaPublicKey);
```
##License
Code and documentation copyright 2015 Benjamin Lu. Code released under the MIT license.