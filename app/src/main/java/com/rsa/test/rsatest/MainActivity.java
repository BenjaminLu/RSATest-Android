package com.rsa.test.rsatest;

import android.app.Activity;
import android.os.AsyncTask;
import android.os.Bundle;
import android.util.Base64;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.Button;
import android.widget.Toast;

import com.github.kevinsawicki.http.HttpRequest;

import org.apache.http.HttpResponse;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;


public class MainActivity extends Activity
{
    private Button button;

    @Override
    protected void onCreate(Bundle savedInstanceState)
    {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        //Test Code
        final String m = "Hello World!";
        KeyPair keyPair = RSA.generateKeyPair();
        final RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        final BigInteger publicExponent = publicKey.getPublicExponent();
        final BigInteger modulus = publicKey.getModulus();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        BigInteger privateExponent = privateKey.getPrivateExponent();

        System.out.println("publicExponent : " + publicExponent.toString());
        System.out.println("modulus : " + modulus.toString());
        System.out.println("privateExponent : " + privateExponent.toString());

        final RSAPublicKey publicKey2 = RSA.getPublicKey(modulus, publicExponent);
        RSAPrivateKey privateKey2 = RSA.getPrivateKey(modulus, privateExponent);

        System.out.println("pub : " + String.valueOf(publicKey2.getEncoded()));
        System.out.println("pri : " + String.valueOf(privateKey2.getEncoded()));

        byte[] encrypted = RSA.encrypt(m, publicKey);
        System.out.println(new String(encrypted));

        byte[] decrypted = RSA.decrypt(encrypted, privateKey2);
        System.out.println(new String(decrypted));

        final byte[] signed = RSA.sign(m, privateKey);
        System.out.println("signed : " + new String(signed));
        boolean verify = RSA.verify(m, signed, publicKey2);
        System.out.println("verify : " + verify);

        //Send to server
        button = (Button) findViewById(R.id.send);
        button.setOnClickListener(new View.OnClickListener()
        {
            @Override
            public void onClick(View v)
            {
                System.out.println("message : " + m);
                System.out.println("sign : " + new String(signed));
                new SendSignAsyncTask(signed).execute(m, modulus.toString(), publicExponent.toString());
            }
        });
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu)
    {
        // Inflate the menu; this adds items to the action bar if it is present.
        getMenuInflater().inflate(R.menu.menu_main, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item)
    {
        // Handle action bar item clicks here. The action bar will
        // automatically handle clicks on the Home/Up button, so long
        // as you specify a parent activity in AndroidManifest.xml.
        int id = item.getItemId();

        //noinspection SimplifiableIfStatement
        if (id == R.id.action_settings) {
            return true;
        }

        return super.onOptionsItemSelected(item);
    }

    protected class SendSignAsyncTask extends AsyncTask<String, Void, Boolean>
    {
        byte[] signed;

        SendSignAsyncTask(byte[] signed) {
            this.signed = signed;
        }

        @Override
        protected Boolean doInBackground(String... params)
        {
            String message = params[0];
            String signBase64 = Base64.encodeToString(signed,Base64.DEFAULT);
            String modulus = params[1];
            String publicExponent = params[2];
            System.out.println("message : " + message);
            System.out.println("sign : " + signBase64);
            System.out.println("publicKey : " + publicExponent);

            Map data = new HashMap<>();
            data.put("message", message);
            data.put("sign", signBase64);
            data.put("modulus", modulus);
            data.put("public_exponent", publicExponent);

            boolean verify = false;
            HttpRequest request = HttpRequest.post(getString(R.string.server_url)).form(data);
            if (request.ok()) {
                String response = request.body();
                JSONObject object = null;
                try {
                    object = new JSONObject(response);
                    verify = object.getBoolean("verify");
                    String messageFromServer = object.getString("message");
                    byte[] signFromServer = Base64.decode(object.getString("sign"), Base64.DEFAULT);
                    BigInteger modulusFromServer = new BigInteger(object.getString("modulus"));
                    BigInteger publicExponentFromServer = new BigInteger(object.getString("public_exponent"));
                    RSAPublicKey rsaPublicKey = RSA.getPublicKey(modulusFromServer, publicExponentFromServer);
                    boolean verifyServerMessage = RSA.verify(messageFromServer,signFromServer, rsaPublicKey);
                    System.out.println("verify Server Message : " + verifyServerMessage);
                } catch (JSONException e) {
                    e.printStackTrace();
                    return false;
                }
                return verify;
            }

            return false;
        }

        @Override
        protected void onPostExecute(Boolean verify)
        {
            Toast.makeText(getApplicationContext(), "verify = " + verify, Toast.LENGTH_SHORT).show();
        }
    }
}
