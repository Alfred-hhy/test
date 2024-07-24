package com.example.dataapi.crypto.prf;

import org.scijava.nativelib.NativeLibraryUtil;

public class PRFAesNi implements IPRF {

    static {
        NativeLibraryUtil.loadNativeLibrary(PRFAesNi.class, "fastaes-jni-wrapper");
    }

    private static native byte[] encrypt(byte[] key_oct, byte[] to_encrypt);

    private static native byte[] multiapply(byte[] key_oct, int[] path);

    @Override
    public byte[] apply(byte[] prfKey, byte[] input) {
        return encrypt(prfKey, input);
    }

    @Override
    public native byte[] apply(byte[] prfKey, int input);

    @Override
    public byte[] muliApply(byte[] prfKey, int[] input) {
        return multiapply(prfKey, input);
    }

}
