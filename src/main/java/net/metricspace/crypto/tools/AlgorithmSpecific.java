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

import java.io.IOException;

import java.security.AlgorithmParameters;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.SecretKeySpec;

/**
 * Static methods for handling algorithm-specific {@link
 * java.security.Key} and {@link java.security.AlgorithmParameters} in
 * a general way.  The JCA is a leaky abstraction, and generation of
 * keys and algorithm parameters typically requires cipher-specific
 * knowledge.
 */
final class AlgorithmSpecific {
    /**
     * Private constructor precludes instantiation.
     */
    private AlgorithmSpecific() {}

    /**
     * Generate a {@link java.security.Key} for the {@link
     * javax.crypto.Mac}.
     *
     * @param mac Mac algorithm to use.
     * @param random Random number source to use for key generation.
     * @return A randomly-generated {@link java.security.Key} for
     *         the {@link javax.crypto.Mac}
     */
    public static SecretKey generateMacKey(final Mac mac,
                                           final SecureRandom random) {
        try {
            final KeyGenerator keygen =
                KeyGenerator.getInstance(mac.getAlgorithm());

            keygen.init(random);

            return keygen.generateKey();
        } catch(final NoSuchAlgorithmException e) {
            // The MAC should have a corresponding KeyGenerator
            throw new IllegalStateException(e);
        }
    }

    /**
     * Decode a {@link java.security.Key} for the {@link
     * javax.crypto.Mac} from raw data.
     *
     * @param mac Mac algorithm to use.
     * @param data The raw data for the {@link java.security.Key}.
     * @return A randomly-generated {@link java.security.Key} for
     *         the {@link javax.crypto.Mac}
     */
    public static SecretKey decodeMacKey(final Mac mac,
                                         final byte[] data) {
        try {
            return SecretKeyFactory.getInstance(mac.getAlgorithm())
                .generateSecret(new SecretKeySpec(data, mac.getAlgorithm()));
        } catch(final NoSuchAlgorithmException | InvalidKeySpecException e) {
            // The MAC should have a corresponding KeyGenerator
            throw new IllegalStateException(e);
        }
    }

    /**
     * Generate {@link java.security.AlgorithmParameters} for the
     * {@link javax.crypto.Mac}, or return {@code null} if the chosen
     * MAC {@link javax.crypto.Mac} does not use any parameters.
     *
     * @param mac Mac algorithm to use.
     * @param random Random number source to use for IV generation.
     * @return A randomly-generated {@link
     *         java.security.AlgorithmParameterSpec} for the {@link
     *         javax.crypto.Mac}
     */
    public static AlgorithmParameterSpec
        generateMacParams(final Mac mac,
                          final SecureRandom random) {
        return null;
    }

    /**
     * Decode the {@link java.security.spec.AlgorithmParameterSpec}
     * for the {@link javax.crypto.Mac} from raw data, or return
     * {@code null} if not applicable.
     *
     * @param data The raw data to decode, or {@code null}.
     * @return The decoded {@link
     *         java.security.spec.AlgorithmParameterSpec} for the
     *         {@link javax.crypto.Mac}, or {@code null}.
     */
    public static AlgorithmParameterSpec decodeMacParams(final Mac mac,
                                                         final byte[] data) {
        return null;
    }

    private static <T extends AlgorithmParameterSpec> Class<T>
        getMacParamSpec(final Mac mac) {
        return null;
    }

    /**
     * Decode a {@link java.security.Key} for the {@link
     * javax.crypto.Cipher} from raw data.
     *
     * @param cipher Cipher algorithm to use.
     * @param data The raw data for the {@link java.security.Key}.
     * @return A randomly-generated {@link java.security.Key} for
     *         the {@link javax.crypto.Cipher}
     */
    public static SecretKey decodeCipherKey(final Cipher cipher,
                                            final byte[] data) {
        try {
            return SecretKeyFactory.getInstance(cipher.getAlgorithm())
                .generateSecret(new SecretKeySpec(data, cipher.getAlgorithm()));
        } catch(final NoSuchAlgorithmException | InvalidKeySpecException e) {
            // The Cipher should have a corresponding KeyGenerator
            throw new IllegalStateException(e);
        }
    }

    /**
     * Generate a {@link java.security.Key} for the {@link
     * javax.crypto.Cipher}.
     *
     * @param mac Mac algorithm to use.
     * @param random Random number source to use for key generation.
     * @return A randomly-generated {@link java.security.Key} for
     *         the {@link javax.crypto.Mac}
     */
    public static SecretKey generateCipherKey(final Cipher cipher,
                                              final SecureRandom random) {
        try {
            final KeyGenerator keygen =
                KeyGenerator.getInstance(cipher.getAlgorithm());

            keygen.init(random);

            return keygen.generateKey();
        } catch(final NoSuchAlgorithmException e) {
            // The MAC should have a corresponding KeyGenerator
            throw new IllegalStateException(e);
        }
    }

    /**
     * Decode the {@link java.security.AlgorithmParameters} for
     * the {@link javax.crypto.Cipher} from raw data.
     *
     * @param data The raw data to decode.
     * @return The decoded {@link
     *         java.security.AlgorithmParameters} for the {@link
     *         javax.crypto.Cipher}.
     */
    public static AlgorithmParameters
        decodeCipherParams(final Cipher cipher,
                           final byte[] data)
        throws IOException {
        try {
            final AlgorithmParameters out =
                AlgorithmParameters.getInstance(cipher.getAlgorithm());

            out.init(data);

            return out;
        } catch(final NoSuchAlgorithmException e) {
            // The MAC should have a corresponding KeyGenerator
            throw new IllegalStateException(e);
        }
    }

    /**
     * Generate {@link java.security.AlgorithmParameters} for the
     * {@link javax.crypto.Cipher}, or return {@code null} if the
     * chosen MAC {@link javax.crypto.Cipher} does not use any
     * parameters.
     *
     * @param cipher Cipher algorithm to use.
     * @param random Random number source to use for IV generation.
     * @return A randomly-generated {@link
     *         java.security.AlgorithmParameters} for the {@link
     *         javax.crypto.Mac}
     */
    public static AlgorithmParameters
        generateCipherParams(final Cipher cipher,
                             final SecureRandom random) {
        return null;
    }
}
