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
import java.io.InputStream;
import java.io.OutputStream;

import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidKeyException;
import java.security.InvalidAlgorithmParameterException;
import java.security.spec.AlgorithmParameterSpec;

import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.Mac;

import net.metricspace.crypto.exceptions.IntegrityCheckException;

/**
 * Authenticated symmetric encryption primitive.  {@code Box}es are a
 * wrapper for symmetric encryption with authentication with
 * single-use keys.  The {@code Box} API is specifically designed to
 * prevent the reuse of {@code Key}s.
 */
public abstract class AbstractBox<T, K extends AbstractBox.Keys> {

    public static class Keys {
        /**
         * Cipher to use to decrypt the contents.
         */
        public final String cipher;

        /**
         * MAC to use to authenticate the contents.
         */
        public final String mac;

        /**
         * {@link java.security.Key} used for decrypting the contents.
         */
        public final Key cipherKey;

        /**
         * {@link java.security.Key} used for authenticating the contents.
         */
        public final Key macKey;

        public final AlgorithmParameterSpec cipherParams;

        public final AlgorithmParameterSpec macParams;

        /**
         * Initialize {@code Keys} for a {@code Box} from the basic
         * components.
         *
         * @param cipher Cipher specification used to decrypt the {@code Box}.
         * @param cipher MAC specification used to authenticate the {@code Box}.
         * @param decrypt {@link java.security.Key} used for
         *                decrypting the {@code Box}.
         * @param auth {@link java.security.Key} used for
         *             authenticating the {@code Box}.
         */
        public Keys(final String cipher,
                    final String mac,
                    final Key cipherKey,
                    final Key macKey,
                    final AlgorithmParameterSpec cipherParams,
                    final AlgorithmParameterSpec macParams) {
            this.cipher = cipher;
            this.mac = mac;
            this.cipherKey = cipherKey;
            this.macKey = macKey;
            this.cipherParams = cipherParams;
            this.macParams = macParams;
        }
    }

    /**
     * A {@code Box} and its corresponding {@code Keys}.
     */
    public static final class BoxKeys<T, B extends AbstractBox<T, K>,
                                      K extends Keys> {
        /**
         * The {@code Box}.
         */
        public final B box;

        /**
         * The {@code Keys} corresponding to the {@code Box}.
         */
        public final K keys;

        public BoxKeys(final B box,
                       final K keys) {
            this.box = box;
            this.keys = keys;
        }
    }

    /**
     * The encrypted data.
     */
    private final byte[] data;

    /**
     * The MAC code.
     */
    private final byte[] code;

    /**
     * Initialize an {@code AbstractBox} from its components.
     *
     * @param data The encrypted data.
     * @param mac The MAC code.
     */
    protected AbstractBox(final byte[] data,
                          final byte[] code) {
        this.data = data;
        this.code = code;
    }

    /**
     * Perform authentication on the box contents.
     *
     * @param keys {@code Keys} to use.
     * @return Whether authentication succeeds with the given keys.
     */
    private boolean authenticate(final K keys)
        throws InvalidAlgorithmParameterException, InvalidKeyException,
               NoSuchAlgorithmException, NoSuchPaddingException {
        final Mac mac = Mac.getInstance(keys.mac);

        mac.init(keys.macKey, keys.macParams);

        final byte[] code = mac.doFinal(data);

        return Arrays.equals(code, this.code);
    }

    /**
     * Decrypt the box contents.  No authentication in performed.
     *
     * @param keys {@code Keys} to use.
     * @return The raw decrypted contents.
     */
    private CipherInputStream decrypt(final K keys)
        throws InvalidAlgorithmParameterException, InvalidKeyException,
               NoSuchAlgorithmException, NoSuchPaddingException {
        final Cipher cipher = Cipher.getInstance(keys.cipher);

        cipher.init(Cipher.DECRYPT_MODE, keys.cipherKey, keys.cipherParams);

        return new CipherInputStream(new ByteArrayInputStream(data), cipher);
    }

    /**
     * Obtain the raw decrypted contents.
     *
     * @param keys {@code Keys} to use.
     * @return A stream containing the raw contents of the {@code Box}.
     * @throws IntegrityCheckException If MAC verification fails.
     */
    public final CipherInputStream unlockRaw(final K keys)
        throws IntegrityCheckException, InvalidAlgorithmParameterException,
               InvalidKeyException, NoSuchAlgorithmException,
               NoSuchPaddingException {
        if (!authenticate(keys)) {
            throw new IntegrityCheckException(keys.mac);
        }

        return decrypt(keys);
    }

}
