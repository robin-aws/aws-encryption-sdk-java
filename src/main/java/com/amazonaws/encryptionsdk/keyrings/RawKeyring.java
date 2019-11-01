/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"). You may not use this file except
 * in compliance with the License. A copy of the License is located at
 *
 * http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */

package com.amazonaws.encryptionsdk.keyrings;

import com.amazonaws.encryptionsdk.EncryptedDataKey;
import com.amazonaws.encryptionsdk.internal.JceKeyCipher;
import com.amazonaws.encryptionsdk.internal.Utils;
import com.amazonaws.encryptionsdk.model.DecryptionMaterials;
import com.amazonaws.encryptionsdk.model.EncryptionMaterials;
import com.amazonaws.encryptionsdk.model.KeyBlob;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.List;
import java.util.logging.Logger;

import static org.apache.commons.lang3.Validate.notBlank;
import static org.apache.commons.lang3.Validate.notNull;

/**
 * A keyring supporting local encryption and decryption using either RSA or AES-GCM.
 */
public class RawKeyring implements Keyring {

    private final String keyNamespace;
    private final String keyName;
    private final JceKeyCipher jceKeyCipher;
    private static final Charset KEY_NAME_ENCODING = StandardCharsets.UTF_8;
    private static final Logger LOGGER = Logger.getLogger(RawKeyring.class.getName());

    static Keyring aes(String keyNamespace, String keyName, SecretKey wrappingKey) {
        return new RawKeyring(keyNamespace, keyName, JceKeyCipher.aesGcm(wrappingKey));
    }

    static Keyring rsa(String keyNamespace, String keyName, PublicKey publicKey, PrivateKey privateKey, String transformation) {
        return new RawKeyring(keyNamespace, keyName, JceKeyCipher.rsa(publicKey, privateKey, transformation));
    }

    private RawKeyring(final String keyNamespace, final String keyName, JceKeyCipher jceKeyCipher) {
        notBlank(keyNamespace, "keyNamespace is required");
        notBlank(keyName, "keyName is required");
        notNull(jceKeyCipher, "jceKeyCipher is required");

        this.keyNamespace = keyNamespace;
        this.keyName = keyName;
        this.jceKeyCipher = jceKeyCipher;
    }

    @Override
    public void onEncrypt(EncryptionMaterials encryptionMaterials) {
        notNull(encryptionMaterials, "encryptionMaterials are required");

        if (encryptionMaterials.getCleartextDataKey() == null) {
            generateDataKey(encryptionMaterials);
        }

        final SecretKey cleartextDataKey = encryptionMaterials.getCleartextDataKey();

        if (!cleartextDataKey.getAlgorithm().equalsIgnoreCase(encryptionMaterials.getAlgorithm().getDataKeyAlgo())) {
            throw new IllegalArgumentException("Incorrect key algorithm. Expected " + cleartextDataKey.getAlgorithm()
                    + " but got " + encryptionMaterials.getAlgorithm().getDataKeyAlgo());
        }

        final EncryptedDataKey encryptedDataKey = jceKeyCipher.encryptKey(
                cleartextDataKey.getEncoded(), keyName, keyNamespace, encryptionMaterials.getEncryptionContext());
        encryptionMaterials.getEncryptedDataKeys().add(new KeyBlob(encryptedDataKey));

        encryptionMaterials.getKeyringTrace().add(keyNamespace, keyName, KeyringTraceFlag.ENCRYPTED_DATA_KEY);
    }

    @Override
    public void onDecrypt(DecryptionMaterials decryptionMaterials, List<EncryptedDataKey> encryptedDataKeys) {
        notNull(decryptionMaterials, "decryptionMaterials are required");
        notNull(encryptedDataKeys, "encryptedDataKeys are required");

        if (decryptionMaterials.getCleartextDataKey() != null) {
            return;
        }

        final byte[] keyNameBytes = keyName.getBytes(KEY_NAME_ENCODING);

        for (EncryptedDataKey encryptedDataKey : encryptedDataKeys) {
            if (!keyNamespace.equals(encryptedDataKey.getProviderId())) {
                continue;
            }

            if (!Utils.arrayPrefixEquals(encryptedDataKey.getProviderInformation(), keyNameBytes, keyNameBytes.length)) {
                continue;
            }

            try {
                final byte[] decryptedKey = jceKeyCipher.decryptKey(
                        encryptedDataKey, keyName, decryptionMaterials.getEncryptionContext());
                decryptionMaterials.setCleartextDataKey(
                        new SecretKeySpec(decryptedKey, decryptionMaterials.getAlgorithm().getDataKeyAlgo()));
                decryptionMaterials.getKeyringTrace().add(keyNamespace, keyName, KeyringTraceFlag.DECRYPTED_DATA_KEY);
                return;
            } catch (Exception e) {
                LOGGER.info("Could not decrypt key due to: " + e.getMessage());
            }
        }

        LOGGER.warning("Could not decrypt any data keys");
    }

    private void generateDataKey(EncryptionMaterials encryptionMaterials) {
        if (encryptionMaterials.getCleartextDataKey() != null) {
            throw new IllegalStateException("Plaintext data key already exists");
        }

        final byte[] rawKey = new byte[encryptionMaterials.getAlgorithm().getDataKeyLength()];
        Utils.getSecureRandom().nextBytes(rawKey);
        final SecretKey key = new SecretKeySpec(rawKey, encryptionMaterials.getAlgorithm().getDataKeyAlgo());

        encryptionMaterials.setCleartextDataKey(key);
        encryptionMaterials.getKeyringTrace().add(keyNamespace, keyName, KeyringTraceFlag.GENERATED_DATA_KEY);
    }
}
