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

public class TaggedBox<T> extends AbstractBox<T, AbstractBox.Keys> {

    public static final class Tag {
        /**
         * The tag portion for the cipher key.
         */
        public final byte[] cipherKey;

        /**
         * The tag portion for the mac key.
         */
        public final byte[] macKey;

        /**
         * The tag portion for the cipher parameters.
         */
        public final byte[] cipherParams;

        /**
         * The tag portion for the mac parameters.
         */
        public final byte[] macParams;

        public Tag(final byte[] cipherKey,
                   final byte[] macKey,
                   final byte[] cipherParams,
                   final byte[] macParams) {
            this.cipherKey = cipherKey;
            this.macKey = macKey;
            this.cipherParams = cipherParams;
            this.macParams = macParams;
        }
    }

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
