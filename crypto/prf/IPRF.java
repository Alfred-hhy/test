package com.example.dataapi.crypto.prf;

public interface IPRF {


        byte[] apply(byte[] prfKey, byte[] input);

        byte[] apply(byte[] prfKey, int input);

        byte[] muliApply(byte[] prfKey, int[] inputs);

}
