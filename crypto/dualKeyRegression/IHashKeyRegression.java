package com.example.dataapi.crypto.dualKeyRegression;

import com.example.dataapi.crypto.prf.IPRF;

public interface IHashKeyRegression {

    //利用双哈希链生成密钥（双令牌生成密钥）
    byte[] getKey(long id);

    //利用id获得相应令牌 前向
    byte[] getNodeSeed1(long id);

    //利用id获得相应令牌 后向
    byte[] getNodeSeed2(long id);

    //prf
    IPRF getPRF();




}
