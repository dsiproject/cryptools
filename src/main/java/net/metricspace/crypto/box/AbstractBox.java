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
package net.metricspace.crypto.box;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.Mac;
import javax.crypto.SecretKey;

import javax.security.auth.DestroyFailedException;

import net.metricspace.crypto.exceptions.IntegrityCheckException;

import net.metricspace.crypto.tools.AlgorithmSpecific;

/**
 * Common superclass for box-like constructions.  This contains most
 * of the logic for implementing various kinds of boxes.
 *
 * @see net.metricspace.crypto.box.Box
 * @see net.metricspace.crypto.box.TaggedBox
 */
abstract class AbstractBox<S extends AbstractBox.Secret>
    extends Authenticated<S> {

    /**
     * Secret for authenticating and unlocking an {@code AbstractBox}.
     */
    public static abstract class Secret extends Authenticated.Secret {
        /**
         * Cipher to use to decrypt the contents.
         */
        public final String cipher;

        /**
         * The {@link java.security.Key} for the {@link
         * javax.crypto.Cipher}.
         */
        protected final SecretKey cipherKey;

        /**
         * The {@link java.security.AlgorithmParameters} for the {@link
         * javax.crypto.Cipher}.
         */
        protected final AlgorithmParameters cipherParams;

        /**
         * Initialize {@code Secret} for an {@code AbstractBox} from
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
         * @throws NoSuchAlgorithmException If {@code cipher} or
         *                                  {@code mac} do not refer
         *                                  to a registered algorithm
         *                                  instance.
         * @throws NoSuchPaddingException If {@code cipher} refers to
         *                                a padding algorithm which
         *                                does not have a registered
         *                                instance.
         */
        protected Secret(final String cipher,
                         final SecretKey cipherKey,
                         final AlgorithmParameters cipherParams,
                         final String mac,
                         final SecretKey macKey,
                         final AlgorithmParameterSpec macParams)
            throws NoSuchAlgorithmException, NoSuchPaddingException {
            this(Cipher.getInstance(cipher), cipherKey, cipherParams,
                 Mac.getInstance(mac), macKey, macParams);
        }

        /**
         * Initialize {@code Secret} for an {@code AbstractBox} from
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
        protected Secret(final Cipher cipher,
                         final SecretKey cipherKey,
                         final AlgorithmParameters cipherParams,
                         final Mac mac,
                         final SecretKey macKey,
                         final AlgorithmParameterSpec macParams) {
            super(mac, macKey, macParams);

            this.cipher = cipher.getAlgorithm();
            this.cipherKey = cipherKey;
            this.cipherParams = cipherParams;
        }

        /**
         * Initialize {@code Secret} for an {@code AbstractBox} from
         * the the basic components for the cipher, and raw data for
         * the MAC.
         *
         * @param cipher Cipher algorithm to use.
         * @param cipherKey The {@link java.security.Key} to use with
         *                  the {@link javax.crypto.Cipher}.
         * @param cipherParams The {@link
         *                     java.security.AlgorithmParameters} to
         *                     use with the {@link
         *                     javax.crypto.Cipher}.
         * @param mac The MAC algorithm to use.
         * @param macKeyData The raw data to use as the MAC key.
         * @param macIVData The raw data to use as the MAC IV, or
         *                  {@code null}.
         * @throws NoSuchAlgorithmException If {@code cipher} or
         *                                  {@code mac} do not refer
         *                                  to a registered algorithm
         *                                  instance.
         * @throws NoSuchPaddingException If {@code cipher} refers to
         *                                a padding algorithm which
         *                                does not have a registered
         *                                instance.
         */
        private Secret(final String cipher,
                       final SecretKey cipherKey,
                       final AlgorithmParameters cipherParams,
                       final String mac,
                       final byte[] macKeyData,
                       final byte[] macIVData)
            throws NoSuchAlgorithmException, NoSuchPaddingException {
            this(Cipher.getInstance(cipher), cipherKey, cipherParams,
                 Mac.getInstance(mac), macKeyData, macIVData);
        }

        /**
         * Initialize {@code Secret} for an {@code AbstractBox} from
         * the the basic components for the cipher, and raw data for
         * the MAC.
         *
         * @param cipher Cipher algorithm to use.
         * @param cipherKey The {@link java.security.Key} to use with
         *                  the {@link javax.crypto.Cipher}.
         * @param cipherParams The {@link
         *                     java.security.AlgorithmParameters} to
         *                     use with the {@link
         *                     javax.crypto.Cipher}.
         * @param mac The MAC algorithm to use.
         * @param macKeyData The raw data to use as the MAC key.
         * @param macIVData The raw data to use as the MAC IV, or
         *                  {@code null}.
         */
        private Secret(final Cipher cipher,
                       final SecretKey cipherKey,
                       final AlgorithmParameters cipherParams,
                       final Mac mac,
                       final byte[] macKeyData,
                       final byte[] macIVData) {
            super(mac, macKeyData, macIVData);

            this.cipher = cipher.getAlgorithm();
            this.cipherKey = cipherKey;
            this.cipherParams = cipherParams;
        }

        /**
         * Initialize {@code Secret} for an {@code AbstractBox} from
         * the basic components.
         *
         * @param cipher Cipher algorithm to use.
         * @param cipherKeyData The raw data to use as the cipher key.
         * @param cipherParamsData The raw data to use as the cipher parameters.
         * @param mac The MAC algorithm to use.
         * @param macKeyData The raw data to use as the MAC key.
         * @param macIVData The raw data to use as the MAC IV, or
         *                  {@code null}.
         * @throws IOException If a low-level IO error occurs.
         * @throws NoSuchAlgorithmException If {@code cipher} or
         *                                  {@code mac} do not refer
         *                                  to a registered algorithm
         *                                  instance.
         * @throws NoSuchPaddingException If {@code cipher} refers to
         *                                a padding algorithm which
         *                                does not have a registered
         *                                instance.
         */
        protected Secret(final String cipher,
                         final byte[] cipherKeyData,
                         final byte[] cipherParamsData,
                         final String mac,
                         final byte[] macKeyData,
                         final byte[] macIVData)
            throws NoSuchAlgorithmException, NoSuchPaddingException,
                   IOException {
            this(Cipher.getInstance(cipher), cipherKeyData, cipherParamsData,
                 Mac.getInstance(mac), macKeyData, macIVData);
        }

        /**
         * Initialize {@code Secret} for an {@code AbstractBox} from
         * the basic components.
         *
         * @param cipher Cipher algorithm to use.
         * @param cipherKeyData The raw data to use as the cipher key.
         * @param cipherParamsData The raw data to use as the cipher parameters.
         * @param mac The MAC algorithm to use.
         * @param macKeyData The raw data to use as the MAC key.
         * @param macIVData The raw data to use as the MAC IV, or
         *                  {@code null}.
         * @throws IOException If a low-level IO error occurs.
         */
        protected Secret(final Cipher cipher,
                         final byte[] cipherKeyData,
                         final byte[] cipherParamsData,
                         final Mac mac,
                         final byte[] macKeyData,
                         final byte[] macIVData)
            throws IOException {
            this(cipher,
                 AlgorithmSpecific.decodeCipherKey(cipher, cipherKeyData),
                 AlgorithmSpecific.decodeCipherParams(cipher, cipherParamsData),
                 mac, macKeyData, macIVData);
        }

        /**
         * Initialize {@code Secret} for an {@code AbstractBox} from
         * the the basic components for the cipher, and a random
         * source the MAC.
         *
         * @param cipher Cipher algorithm to use.
         * @param cipherKey The {@link java.security.Key} to use with
         *                  the {@link javax.crypto.Cipher}.
         * @param cipherParams The {@link
         *                     java.security.AlgorithmParameters} to
         *                     use with the {@link
         *                     javax.crypto.Cipher}.
         * @param mac The MAC algorithm to use.
         * @param random The random source to use.
         * @throws NoSuchAlgorithmException If {@code cipher} or
         *                                  {@code mac} do not refer
         *                                  to a registered algorithm
         *                                  instance.
         * @throws NoSuchPaddingException If {@code cipher} refers to
         *                                a padding algorithm which
         *                                does not have a registered
         *                                instance.
         */
        private Secret(final String cipher,
                       final SecretKey cipherKey,
                       final AlgorithmParameters cipherParams,
                       final String mac,
                       final SecureRandom random)
            throws NoSuchAlgorithmException, NoSuchPaddingException {
            this(Cipher.getInstance(cipher), cipherKey, cipherParams,
                 Mac.getInstance(mac), random);
        }

        /**
         * Initialize {@code Secret} for an {@code AbstractBox} from
         * the the basic components for the cipher, and a random
         * source for the MAC.
         *
         * @param cipher Cipher algorithm to use.
         * @param cipherKey The {@link java.security.Key} to use with
         *                  the {@link javax.crypto.Cipher}.
         * @param cipherParams The {@link
         *                     java.security.AlgorithmParameters} to
         *                     use with the {@link
         *                     javax.crypto.Cipher}.
         * @param mac The MAC algorithm to use.
         * @param random The random source to use.
         */
        private Secret(final Cipher cipher,
                       final SecretKey cipherKey,
                       final AlgorithmParameters cipherParams,
                       final Mac mac,
                       final SecureRandom random) {
            super(mac, random);

            this.cipher = cipher.getAlgorithm();
            this.cipherKey = cipherKey;
            this.cipherParams = cipherParams;
        }

        /**
         * Initialize {@code Secret} for an {@code AbstractBox} from
         * a random source.
         *
         * @param cipher Cipher algorithm to use.
         * @param mac The MAC algorithm to use.
         * @param random The random source to use.
         * @throws NoSuchAlgorithmException If {@code cipher} or
         *                                  {@code mac} do not refer
         *                                  to a registered algorithm
         *                                  instance.
         * @throws NoSuchPaddingException If {@code cipher} refers to
         *                                a padding algorithm which
         *                                does not have a registered
         *                                instance.
         */
        protected Secret(final String cipher,
                         final String mac,
                         final SecureRandom random)
            throws NoSuchAlgorithmException, NoSuchPaddingException {
            this(Cipher.getInstance(cipher), Mac.getInstance(mac), random);
        }

        /**
         * Initialize {@code Secret} for an {@code AbstractBox} from
         * a random source.
         *
         * @param cipher Cipher algorithm to use.
         * @param mac The MAC algorithm to use.
         * @param random The random source to use.
         */
        protected Secret(final Cipher cipher,
                         final Mac mac,
                         final SecureRandom random) {
            this(cipher,
                 AlgorithmSpecific.generateCipherKey(cipher, random),
                 AlgorithmSpecific.generateCipherParams(cipher, random),
                 mac, random);
        }

        /**
         * Get a fully-initialized {@link javax.crypto.Cipher} instance
         * using this {@code Secret}.
         *
         * @param mode The cipher mode to use.
         * @return A fully-initialized {@link javax.crypto.Cipher}
         *         instance using this {@code Secret}.
         * @throws IllegalStateException If the {@link
         *                               javax.crypto.Cipher} could
         *                               not be initialized, possibly
         *                               due to registered algorithms
         *                               changing since the {@code
         *                               AbstractBox} was created.
         */
        public final Cipher getCipher(final int mode) {
            try {
                final Cipher out = Cipher.getInstance(cipher);

                out.init(Cipher.DECRYPT_MODE, cipherKey, cipherParams);

                return out;
            } catch(final InvalidAlgorithmParameterException |
                          InvalidKeyException |
                          NoSuchAlgorithmException |
                          NoSuchPaddingException e) {
                throw new IllegalStateException(e);
            }
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public void destroy()
            throws DestroyFailedException {
            super.destroy();
            cipherKey.destroy();
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public boolean isDestroyed() {
            return super.isDestroyed() && cipherKey.isDestroyed();
        }
    }

    /**
     * The encrypted data.
     */
    private final byte[] data;

    /**
     * Initialize an {@code AbstractBox} from its components.
     *
     * @param data The encrypted data.
     * @param code The MAC code.
     */
    protected AbstractBox(final byte[] data,
                          final byte[] code) {
        super(code);
        this.data = data;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected void insertData(final Mac mac) {
        mac.update(data);
    }

    /**
     * Obtain the decrypted contents.
     *
     * @param secret {@code Secret} to use.
     * @return A stream containing the raw contents of the {@code Box}.
     * @throws IntegrityCheckException If MAC verification fails.
     */
    public final CipherInputStream unlock(final S secret)
        throws IntegrityCheckException {
        if (!verify(secret)) {
            throw new IntegrityCheckException(secret.mac);
        }

        return unlockUnverified(secret);
    }

    /**
     * Obtain the decrypted contents, without performing verification
     *
     * @param secret {@code Secret} to use.
     * @return A stream containing the raw contents of the {@code Box}.
     */
    public final CipherInputStream unlockUnverified(final S secret) {
        return new CipherInputStream(new ByteArrayInputStream(data),
                                     secret.getCipher(Cipher.DECRYPT_MODE));
    }
}
