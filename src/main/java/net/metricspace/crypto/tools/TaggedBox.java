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
import java.io.InputStream;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;

import javax.security.auth.DestroyFailedException;

import net.metricspace.crypto.exceptions.IntegrityCheckException;

/**
 * Boxes tagged with additional information allowing their {@link
 * TaggedBox.Secret}s be recovered from secret bytestring, such as a
 * password.  This is accomplished by storing information in a {@link
 * TaggedBox.Tag}, which is combined with the secret bytestring and
 * hashed to produce the {@link TaggedBox.Secret} which unlocks the
 * box.
 *
 * The reconstructed {@link TaggedBox.Secret} can be safely shared
 * without divulging the secret bytestring; reconstructing it would
 * require both reversing a secure deterministic pseudorandom
 * generator and then pre-imaging the hash function used to compute its
 * seed.
 */
public class TaggedBox extends AbstractBox<TaggedBox.Secret> {
    /**
     * Data used to reconstruct a {@link Secret} from a secret
     * bytestring.  This includes the names of the algorithms, as well
     * as a tag, which is concatenated to the secret bytestring,
     * hashed, then used as a seed to a deterministic pseudorandom
     * function.
     */
    public static final class Tag extends Authenticated<Tag.Secret> {
        /**
         * Authentication secret for {@code Tag}s only.
         */
        public static final class Secret extends Authenticated.Secret {
            /**
             * Initialize this {@code Secret} from its essential data.
             *
             * @param mac The MAC algorithm to use.
             * @param macKeyData The raw data to use as the key.
             * @param macParamsData The raw data to use as the MAC
             *                      parameters, or {@code null}.
             */
            public Secret(final String mac,
                          final byte[] macKeyData,
                          final byte[] macParamsData)
                throws NoSuchAlgorithmException {
                super(mac, macKeyData, macParamsData);
            }
        }

        /**
         * Algorithm specifier for the {@link javax.crypto.Mac} used
         * to authenticate the box contents.
         */
        public final String mac;

        /**
         * Algorithm specifier for the {@link javax.crypto.Cipher} used
         * to encrypt the box contents.
         */
        public final String cipher;

        /**
         * Algorithm specifier for the {@link
         * java.security.MessageDigest} used to generate the seed for
         * the deterministic pseudorandom generator.
         */
        public final String hash;

        /**
         * Algorithm specifier for the {@link
         * java.security.SecureRandom}, which must be a deterministic
         * generator, which is used to generate keys and IVs for the
         * {@link javax.crypto.Mac} and {@link javax.crypto.Cipher}.
         */
        public final String drbg;

        /**
         * The tag data.
         */
        public final byte[] tag;

        /**
         * Initialize a {@code Tag} from its essential components.
         *
         * @param mac The algorithm specifier for the {@link javax.crypto.Mac}.
         * @param cipher The algorithm specifier for the {@link
         *               javax.crypto.Cipher}
         * @param hash The algorithm specifier for the {@link
         *             java.security.MessageDigest}
         * @param drbg The algorithm specifier for the {@link
         *             java.security.SecureRandom}
         * @param tag The data to be appendend to a secret bytestring
         *            to reconstruct the {@link TaggedBox.Secret}.
         * @param code The MAC code used to authenticate this {@code Tag}.
         */
        public Tag(final String mac,
                   final String cipher,
                   final String hash,
                   final String drbg,
                   final byte[] tag,
                   final byte[] code) {
            super(code);

            this.mac = mac;
            this.cipher = cipher;
            this.hash = hash;
            this.drbg = drbg;
            this.tag = tag;
        }

        /**
         * {@inheritDoc}
         */
        @Override
        protected void insertData(final Mac m) {
            m.update(mac.getBytes());
            m.update(cipher.getBytes());
            m.update(hash.getBytes());
            m.update(drbg.getBytes());
            m.update(tag);
        }
    }

    public final class Secret extends AbstractBox.Secret {
        /**
         * Secret for use for authenticating {@link Tag}s.
         */
        private final Tag.Secret tagAuth;

        /**
         * Initialize {@code Secret} for a {@code TaggedBox} from the
         * basic components.
         *
         * @param cipher Cipher specification used to decrypt the {@code Box}.
         * @param cipherKeyData The raw data to use as the cipher key.
         * @param cipherParamsData The raw data to use as the cipher parameters.
         * @param mac The MAC algorithm to use.
         * @param macKeyData The raw data to use as the MAC key.
         * @param macIVData The raw data to use as the MAC IV, or
         *                  {@code null}.
         */
        private Secret(final String cipher,
                       final byte[] cipherKeyData,
                       final byte[] cipherParamsData,
                       final String mac,
                       final byte[] macKeyData,
                       final byte[] macIVData,
                       final Tag.Secret tagAuth)
            throws NoSuchAlgorithmException, NoSuchPaddingException,
                   IOException {
            super(cipher, cipherKeyData, cipherParamsData,
                  mac, macKeyData, macIVData);

            this.tagAuth = tagAuth;
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public void destroy()
            throws DestroyFailedException {
            super.destroy();
            tagAuth.destroy();
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public boolean isDestroyed() {
            return super.isDestroyed() && tagAuth.isDestroyed();
        }
    }

    /**
     * The {@link Tag} used to recover the {@link Secret} for this
     * {@code TaggedBox}.
     */
    private final Tag tag;

    /**
     * Create a box from its components.
     *
     * @param data The encrypted data.
     * @param mac The MAC code.
     */
    private TaggedBox(final byte[] data,
                      final byte[] code,
                      final Tag tag) {
        super(data, code);

        this.tag = tag;
    }

}
