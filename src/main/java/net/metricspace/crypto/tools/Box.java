/* Copyright (c) 2018, Eric McCorkle.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * * Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in
 *   the documentation and/or other materials provided with the
 *   distribution.
 *
 * * Neither the name of the copyright holder nor the names of its
 *   contributors may be used to endorse or promote products derived
 *   from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */
package net.metricspace.crypto.tools;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import java.security.AlgorithmParameters;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidKeyException;
import java.security.InvalidAlgorithmParameterException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.SecureRandom;

import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.BadPaddingException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.Mac;
import javax.crypto.SecretKey;

import net.metricspace.crypto.exceptions.IntegrityCheckException;

/**
 * Authenticated symmetric encryption primitive.  {@code Box}es are a
 * wrapper for symmetric encryption with authentication with
 * single-use keys.  The {@code Box} API is specifically designed to
 * prevent the reuse of {@code Key}s.
 */
public final class Box extends AbstractBox<Box.Secret> {

    /**
     * Secret information used to unlock a {@link Box}.
     */
    public static final class Secret extends AbstractBox.Secret {
        /**
         * Initialize {@code Secret} for a {@code Box} from
         * the basic components.
         *
         * @param cipher The cipher algorithm to use.
         * @param cipherKey The {@link java.security.Key} to use with
         *                  the {@link javax.crypto.Cipher}.
         * @param cipherParams The {@link
         *                     java.security.AlgorithmParameters} to
         *                     use with the {@link
         *                     javax.crypto.Cipher}.
         * @param mac The MAC algorithm to use.
         * @param macKey The {@link java.security.Key} to use.
         * @param macParams The {@link
         *                  java.security.spec.AlgorithmParameterSpec} for
         *                  the {@link javax.crypto.Mac}, or {@code
         *                  null}.
         */
        public Secret(final String cipher,
                      final SecretKey cipherKey,
                      final AlgorithmParameters cipherParams,
                      final String mac,
                      final SecretKey macKey,
                      final AlgorithmParameterSpec macParams)
            throws NoSuchAlgorithmException, NoSuchPaddingException {
            super(cipher, cipherKey, cipherParams, mac, macKey, macParams);
        }

        /**
         * Initialize {@code Secret} for a {@code Box} from the basic
         * components.
         *
         * @param cipher The cipher algorithm to use.
         * @param cipherKey The {@link java.security.Key} to use with
         *                  the {@link javax.crypto.Cipher}.
         * @param cipherParams The {@link
         *                     java.security.AlgorithmParameters} to
         *                     use with the {@link
         *                     javax.crypto.Cipher}.
         * @param mac The MAC algorithm to use.
         * @param macKey The {@link java.security.Key} to use.
         * @param macParams The {@link
         *                  java.security.spec.AlgorithmParameterSpec} for
         *                  the {@link javax.crypto.Mac}, or {@code
         *                  null}.
         */
        public Secret(final Cipher cipher,
                      final SecretKey cipherKey,
                      final AlgorithmParameters cipherParams,
                      final Mac mac,
                      final SecretKey macKey,
                      final AlgorithmParameterSpec macParams) {
            super(cipher, cipherKey, cipherParams, mac, macKey, macParams);
        }

        /**
         * Initialize {@code Secret} for a {@code Box} from the raw
         * data.
         *
         * @param cipher Cipher algorithm to use.
         * @param cipherKeyData The raw data to use as the cipher key.
         * @param cipherParamsData The raw data to use as the cipher parameters.
         * @param mac The MAC algorithm to use.
         * @param macKeyData The raw data to use as the MAC key.
         * @param macParamsData The raw data to use as the MAC params,
         *                      or {@code null}.
         */
        public Secret(final String cipher,
                      final byte[] cipherKeyData,
                      final byte[] cipherParamsData,
                      final String mac,
                      final byte[] macKeyData,
                      final byte[] macParamsData)
            throws NoSuchAlgorithmException, NoSuchPaddingException,
                   IOException {
            super(cipher, cipherKeyData, cipherParamsData,
                  mac, macKeyData, macParamsData);
        }

        /**
         * Initialize {@code Secret} for a {@code Box} from the raw data..
         *
         * @param cipher Cipher algorithm to use.
         * @param cipherKeyData The raw data to use as the cipher key.
         * @param cipherParamsData The raw data to use as the cipher parameters.
         * @param mac The MAC algorithm to use.
         * @param macKeyData The raw data to use as the MAC key.
         * @param macParamsData The raw data to use as the MAC params,
         *                      or {@code null}.
         */
        public Secret(final Cipher cipher,
                      final byte[] cipherKeyData,
                      final byte[] cipherParamsData,
                      final Mac mac,
                      final byte[] macKeyData,
                      final byte[] macParamsData)
            throws IOException {
            super(cipher, cipherKeyData, cipherParamsData,
                  mac, macKeyData, macParamsData);
        }

        /**
         * Initialize {@code Secret} for a {@code Box} from a random
         * source.
         *
         * @param cipher Cipher algorithm to use.
         * @param mac The MAC algorithm to use.
         * @param random The random source to use.
         */
        public Secret(final String cipher,
                      final String mac,
                      final SecureRandom random)
            throws NoSuchAlgorithmException, NoSuchPaddingException {
            super(cipher, mac, random);
        }

        /**
         * Initialize {@code Secret} for a {@code Box} from a random
         * source.
         *
         * @param cipher Cipher algorithm to use.
         * @param mac The MAC algorithm to use.
         * @param random The random source to use.
         */
        public Secret(final Cipher cipher,
                      final Mac mac,
                      final SecureRandom random) {
            super(cipher, mac, random);
        }
    }

    /**
     * Create a box from its components.
     *
     * @param data The encrypted data.
     * @param mac The MAC code.
     */
    private Box(final byte[] data,
                final byte[] code) {
        super(data, code);
    }

    /**
     * A {@code Box} and its corresponding {@code Secret}.
     */
    public static final class NewBox {
        /**
         * The {@code Box}.
         */
        public final Box box;

        /**
         * The {@code Secret} corresponding to the {@code Box}.
         */
        public final AbstractBox.Secret secret;

        public NewBox(final Box box,
                      final Secret secret) {
            this.box = box;
            this.secret = secret;
        }
    }

    public static NewBox create(final String cipher,
                                final String mac,
                                final byte[] data,
                                final SecureRandom random)
        throws BadPaddingException, InvalidAlgorithmParameterException,
               InvalidKeyException, IllegalBlockSizeException,
               NoSuchAlgorithmException, NoSuchPaddingException {
        final Secret secret = new Secret(cipher, mac, random);
        final Cipher c = secret.getCipher(Cipher.ENCRYPT_MODE);
        final Mac m = secret.getMac();
        final byte[] encrypted = c.doFinal(data);
        final byte[] code = m.doFinal(encrypted);
        final Box box = new Box(encrypted, code);

        return new NewBox(box, secret);
    }
}
