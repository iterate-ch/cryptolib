/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptolib.v1;

import static org.cryptomator.cryptolib.v1.Constants.ENC_ALG;
import static org.cryptomator.cryptolib.v1.Constants.KEY_LEN_BYTES;
import static org.cryptomator.cryptolib.v1.Constants.MAC_ALG;

import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.cryptomator.cryptolib.api.CryptorProvider;
import org.cryptomator.cryptolib.api.InvalidPassphraseException;
import org.cryptomator.cryptolib.api.UnsupportedVaultFormatException;
import org.cryptomator.cryptolib.common.AesKeyWrap;
import org.cryptomator.cryptolib.common.MacSupplier;
import org.cryptomator.cryptolib.common.Scrypt;

public class CryptorProviderImpl implements CryptorProvider {

	private final SecureRandom random;
	private final KeyGenerator encKeyGen;
	private final KeyGenerator macKeyGen;

	public CryptorProviderImpl(SecureRandom random) {
		this.random = random;
		try {
			this.encKeyGen = KeyGenerator.getInstance(ENC_ALG);
			encKeyGen.init(KEY_LEN_BYTES * Byte.SIZE, random);
			this.macKeyGen = KeyGenerator.getInstance(MAC_ALG);
			macKeyGen.init(KEY_LEN_BYTES * Byte.SIZE, random);
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException("Hard-coded algorithm doesn't exist.", e);
		}
	}

	@Override
	public CryptorImpl createNew() {
		SecretKey encKey = encKeyGen.generateKey();
		SecretKey macKey = macKeyGen.generateKey();
		return new CryptorImpl(encKey, macKey, random);
	}

	@Override
	public CryptorImpl createFromKeyFile(byte[] keyFileContents, CharSequence passphrase, int expectedVaultVersion) throws UnsupportedVaultFormatException, InvalidPassphraseException {
		final KeyFile keyFile = KeyFile.parse(keyFileContents);
		final byte[] kekBytes = Scrypt.scrypt(passphrase, keyFile.getScryptSalt(), keyFile.getScryptCostParam(), keyFile.getScryptBlockSize(), KEY_LEN_BYTES);
		try {
			SecretKey kek = new SecretKeySpec(kekBytes, ENC_ALG);
			return createFromKeyFile(keyFile, kek, expectedVaultVersion);
		} finally {
			Arrays.fill(kekBytes, (byte) 0x00);
		}
	}

	private CryptorImpl createFromKeyFile(KeyFile keyFile, SecretKey kek, int expectedVaultVersion) throws UnsupportedVaultFormatException, InvalidPassphraseException {
		// check version
		if (expectedVaultVersion != keyFile.getVersion()) {
			throw new UnsupportedVaultFormatException(keyFile.getVersion(), expectedVaultVersion);
		}

		try {
			SecretKey macKey = AesKeyWrap.unwrap(kek, keyFile.getMacMasterKey(), MAC_ALG);
			Mac mac = MacSupplier.HMAC_SHA256.withKey(macKey);
			byte[] versionMac = mac.doFinal(ByteBuffer.allocate(Integer.SIZE / Byte.SIZE).putInt(expectedVaultVersion).array());
			if (keyFile.getVersionMac() == null || !MessageDigest.isEqual(versionMac, keyFile.getVersionMac())) {
				// attempted downgrade attack: versionMac doesn't match version.
				throw new UnsupportedVaultFormatException(Integer.MAX_VALUE, expectedVaultVersion);
			}
			SecretKey encKey = AesKeyWrap.unwrap(kek, keyFile.getEncryptionMasterKey(), ENC_ALG);
			return new CryptorImpl(encKey, macKey, random);
		} catch (InvalidKeyException e) {
			throw new InvalidPassphraseException();
		}
	}

}