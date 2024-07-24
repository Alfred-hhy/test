package com.example.dataapi.crypto.dualKeyRegression;

import com.example.dataapi.crypto.prf.IPRF;
import com.example.dataapi.crypto.prf.PRFFactory;

public class HashKeyRegressionFactory {

    public static IHashKeyRegression getNewDefaultHashKeyRegression(byte[] seed1,byte[] seed2,long length){
        return getNewHashKeyRegression(PRFFactory.getDefaultPRF(),seed1,seed2,length);
    }

    public static IHashKeyRegression getNewHashKeyRegression(IPRF prf,byte[] seed1, byte[] seed2, long length){
       //isowner=true
        return new HashKeyRegression(true,prf,seed1,seed2,length);
    }


}
