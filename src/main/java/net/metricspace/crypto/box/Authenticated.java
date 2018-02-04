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

import java.security.InvalidKeyException;
import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import java.util.Arrays;

import javax.crypto.NoSuchPaddingException;
import javax.crypto.Mac;
import javax.crypto.SecretKey;

import javax.security.auth.DestroyFailedException;
import javax.security.auth.Destroyable;

import net.metricspace.crypto.tools.AlgorithmSpecific;

/**
 * Authenticated objects.  This is a common superclass for objects
 * that can be authenticated against some secret using a MAC
 * algorithm.
 */
public abstract class Authenticated<S extends Authenticated.Secret> {
    /**
     * Secrets against which {@link Authenticated} objects are
     * authenticated.
     */
    public static abstract class Secret implements Destroyable {
        /**
         * MAC to use to authenticate the contents.
         */
        public final String mac;

        /**
         * The {@link java.security.Key} for the {@link
         * javax.crypto.Mac}.
         */
        protected final SecretKey macKey;

        /**
         * The {@link java.security.spec.AlgorithmParameterSpec} for the
         * {@link javax.crypto.Mac}.
         */
        protected final AlgorithmParameterSpec macParams;

        /**
         * Initialize this {@code Secret} from its essential data.
         *
         * @param mac The MAC algorithm to use.
         * @param macKey The {@link java.security.Key} to use.
         * @param macParams The {@link
         *                  java.security.spec.AlgorithmParameterSpec}
         *                  for the {@link javax.crypto.Mac}, or
         *                  {@code null}.
         * @throws NoSuchAlgorithmException If {@code mac} does not
         *                                  refer to a registered
         *                                  algorithm instance.
         */
        protected Secret(final String mac,
                         final SecretKey macKey,
                         final AlgorithmParameterSpec macParams)
            throws NoSuchAlgorithmException {
            this(Mac.getInstance(mac), macKey, macParams);
        }

        /**
         * Initialize this {@code Secret} from its essential data.
         *
         * @param mac The MAC algorithm to use.
         * @param macKey The {@link java.security.Key} to use.
         * @param macParams The {@link
         *                  java.security.spec.AlgorithmParameterSpec} for
         *                  the {@link javax.crypto.Mac}, or {@code
         *                  null}.
         */
        protected Secret(final Mac mac,
                         final SecretKey macKey,
                         final AlgorithmParameterSpec macParams) {
            this.mac = mac.getAlgorithm();
            this.macKey = macKey;
            this.macParams = macParams;
        }

        /**
         * Initialize this {@code Secret} from raw data.
         *
         * @param mac The MAC algorithm to use.
         * @param macKeyData The raw data to use as the key.
         * @param macParamData The raw data to use as the MAC IV, or
         *                     {@code null}.
         * @throws NoSuchAlgorithmException If {@code mac} does not
         *                                  refer to a registered
         *                                  algorithm instance.
         */
        protected Secret(final String mac,
                         final byte[] macKeyData,
                         final byte[] macParamData)
            throws NoSuchAlgorithmException {
            this(Mac.getInstance(mac), macKeyData, macParamData);
        }

        /**
         * Initialize this {@code Secret} from raw data.
         *
         * @param mac The MAC algorithm to use.
         * @param macKeyData The raw data to use as the key.
         * @param macParamData The raw data to use as the MAC params, or
         *                     {@code null}.
         */
        protected Secret(final Mac mac,
                         final byte[] macKeyData,
                         final byte[] macParamData) {
            this(mac, AlgorithmSpecific.decodeMacKey(mac, macKeyData),
                 AlgorithmSpecific.decodeMacParams(mac, macParamData));
        }

        /**
         * Initialize this {@code Secret} from a random source.
         *
         * @param mac The MAC algorithm to use.
         * @param random The random source to use.
         * @throws NoSuchAlgorithmException If {@code mac} does not
         *                                  refer to a registered
         *                                  algorithm instance.
         */
        protected Secret(final String mac,
                         final SecureRandom random)
            throws NoSuchAlgorithmException {
            this(Mac.getInstance(mac), random);
        }

        /**
         * Initialize this {@code Secret} from a random source.
         *
         * @param mac The MAC algorithm to use.
         * @param random The random source to use.
         */
        protected Secret(final Mac mac,
                         final SecureRandom random) {
            this(mac, AlgorithmSpecific.generateMacKey(mac, random),
                 AlgorithmSpecific.generateMacParams(mac, random));
        }

        /**
         * Get a fully-initialized {@link javax.crypto.Mac} instance
         * for authenticating against this {@code Secret}.
         *
         * @return A fully-initialized {@link javax.crypto.Mac}
         *         instance for authenticating against this {@code Secret}.
         */
        public final Mac getMac() {
            try {
                final Mac out = Mac.getInstance(mac);

                if (macParams == null) {
                    out.init(macKey);
                } else {
                    out.init(macKey, macParams);
                }

                return out;
            } catch(final InvalidAlgorithmParameterException |
                          InvalidKeyException |
                          NoSuchAlgorithmException e) {
                throw new IllegalStateException(e);
            }
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public void destroy()
            throws DestroyFailedException {
            macKey.destroy();
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public boolean isDestroyed() {
            return macKey.isDestroyed();
        }
    }

    /**
     * The MAC code.
     */
    private final byte[] code;

    /**
     * Initialize the authenticated object.
     *
     * @param code The MAC code for the underlying data.
     */
    protected Authenticated(final byte[] code) {
        this.code = code;
    }

    /**
     * Add all data for this object into the {@link javax.crypto.Mac}
     * instance.
     *
     * @param mac The {@link javax.crypto.Mac} into which to add all
     *            data.
     */
    protected abstract void insertData(final Mac mac);

    /**
     * Verify the authenticated object.
     *
     * @param secret The {@code Secret to use}.
     * @return Whether or not authentication succeeded.
     */
    public boolean verify(final Secret secret) {
        final Mac mac = secret.getMac();

        insertData(mac);

        final byte[] code = mac.doFinal();

        return Arrays.equals(code, this.code);

    }
}
