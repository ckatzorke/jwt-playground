/*
 * Copyright (C) Christian Katzorke <ckatzorke@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package jwtplayground;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;

import javax.xml.bind.DatatypeConverter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.impl.Base64Codec;
import io.jsonwebtoken.impl.crypto.RsaProvider;

/**
 * @author Christian Katzorke ckatzorke@gmail.com
 *
 */
public class Sample {

	public static void main(String[] args) throws InvalidKeySpecException, NoSuchAlgorithmException {
		// Simple example with a self created keypair about how to sign a JWT
		// token with private key and verifiy it with public
		// the jwt provider generates a 4086 bit key
		KeyPair keyPair = RsaProvider.generateKeyPair();

		System.err.println("Private: " + keyPair.getPrivate());
		String b64PublicKey = DatatypeConverter.printBase64Binary(keyPair.getPublic().getEncoded());
		System.err.println("Public: " + b64PublicKey);

		String s = Jwts.builder().setSubject("ckatzorke")
				.setExpiration(Date.from(LocalDateTime.now().plusMinutes(1).atZone(ZoneId.systemDefault()).toInstant()))
				.signWith(SignatureAlgorithm.RS512, keyPair.getPrivate()).compact();
		System.out.println("This is the base64 encoded token\n\t" + s);

		// now verify, with public key from keypair
		Claims body = Jwts.parser().setSigningKey(keyPair.getPublic()).parseClaimsJws(s).getBody();
		System.out.println("This is the verified and parsed body \n\t" + body);
		System.out.println("And the subject in there is \n\t" + body.getSubject());

		// now create public key from base64 String
		PublicKey publicKeyFromB64String = KeyFactory.getInstance("RSA")
				.generatePublic(new X509EncodedKeySpec(Base64Codec.BASE64.decode(b64PublicKey)));
		body = Jwts.parser().setSigningKey(publicKeyFromB64String).parseClaimsJws(s).getBody();
		System.out.println("This is the verified (from base64 String) and parsed body \n\t" + body);
		System.out.println("And the subject in there is \n\t" + body.getSubject());

	}
}
