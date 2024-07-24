/*
 * Copyright (c) 2020. by ETH Zurich, see AUTHORS file for more
 * Licensed under the Apache License, Version 2.0, see LICENSE file for more details.
 */

package com.example.dataapi.crypto.keymanagement;


import java.math.BigInteger;
import java.util.ArrayList;

import com.example.dataapi.crypto.dualKeyRegression.IHashKeyRegression;
import com.example.dataapi.crypto.keyRegression.IKeyRegression;
import com.example.dataapi.crypto.keyRegression.SeedNode;
import com.example.dataapi.crypto.keyRegression.TreeKeyRegressionFactory;

/**
 * Class for handling all the keys associated with a stream as well as receiving them.
 * 一个数据流密钥管理 getChunkEncryptionKey
 */
public class
StreamKeyManager {

    private final IKeyRegression treeKeyRegression;
    private final byte[] macKey;
    private final byte[] sharingKeystreamMasterKey;
    private boolean isMaster;

    private IHashKeyRegression hashKeyRegression;

    public StreamKeyManager(byte[] streamMasterKey, int numKeysDepth) {
        IKeyRegression keyDerivationTree = TreeKeyRegressionFactory.getNewDefaultKeyRegression(streamMasterKey, 2);
        byte[] metadataEncryptionKey = keyDerivationTree.getSeed(1);
        treeKeyRegression = TreeKeyRegressionFactory.getNewDefaultKeyRegression(metadataEncryptionKey, numKeysDepth);
        macKey = keyDerivationTree.getSeed(2);
        sharingKeystreamMasterKey = keyDerivationTree.getSeed(3);
        isMaster = true;
    }

    public StreamKeyManager(ArrayList<SeedNode> nodes, byte[] macKey, int numKeysDepth) {
        this.treeKeyRegression = TreeKeyRegressionFactory.getNewDefaultKeyRegression(nodes, numKeysDepth);
        this.macKey = macKey;
        sharingKeystreamMasterKey = null;
        isMaster = false;
    }

    public BigInteger getMacKeyAsBigInteger() {
        return new BigInteger(macKey);
    }

    public IKeyRegression getTreeKeyRegression() {
        return treeKeyRegression;
    }

    //从两个密钥中：信封
    public byte[] getChunkEncryptionKey(long chunkId) {
        return KeyUtil.deriveCombinedKey(treeKeyRegression.getPRF(),
                treeKeyRegression.getSeed(chunkId),
                treeKeyRegression.getSeed(chunkId + 1));
    }

    public byte[] getChunkEncryptionKey(long chunkId, CachedKeys keys) {
        if (!keys.containsKeys()) {
            keys.setK1(treeKeyRegression.getSeed(chunkId));
            keys.setK2(treeKeyRegression.getSeed(chunkId + 1));
        }
        return KeyUtil.deriveCombinedKey(treeKeyRegression.getPRF(), keys.k1, keys.k2);
    }

    public byte[] getHashChunkKey(long chunkId){
        return hashKeyRegression.getKey(chunkId);
    }

    public IKeyRegression getSharingKeyRegression(int precision, int depth) {
        if (isMaster) {
            byte[] precisionMasterSecret = this.treeKeyRegression.getPRF().apply(sharingKeystreamMasterKey, precision);
            return TreeKeyRegressionFactory.getNewDefaultKeyRegression(precisionMasterSecret, depth);
        } else {
            throw new RuntimeException("Non-owner is not able to share");
        }
    }

    public boolean isMaster() {
        return this.isMaster;
    }


}
