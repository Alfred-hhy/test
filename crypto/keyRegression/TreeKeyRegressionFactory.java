/*
 * Copyright (c) 2020. by ETH Zurich, see AUTHORS file for more
 * Licensed under the Apache License, Version 2.0, see LICENSE file for more details.
 */

package com.example.dataapi.crypto.keyRegression;

import java.util.ArrayList;

import com.example.dataapi.crypto.prf.IPRF;
import com.example.dataapi.crypto.prf.PRFFactory;

public class TreeKeyRegressionFactory {
    public static IKeyRegression getNewDefaultKeyRegression(byte[] rootSeed, int depth) {
        return getNewKeyRegression(PRFFactory.getDefaultPRF(), rootSeed, depth, 2);
    }

    public static IKeyRegression getNewDefaultKeyRegression(ArrayList<SeedNode> nodes, int depth) {
        return new TreeKeyRegression(false, PRFFactory.getDefaultPRF(), nodes, depth, 2);
    }

    public static IKeyRegression getNewKeyRegression(IPRF prf, byte[] rootSeed, int depth, int kFactor) {
        ArrayList<SeedNode> seeds = new ArrayList<SeedNode>();
        seeds.add(new TreeKeyRegressionNode(rootSeed, 0, 0));
        return new TreeKeyRegression(true, prf, seeds, depth, kFactor);
    }

    public static IKeyRegression getNewDefaultTESTKeyRegression(IPRF prf, int depth) {
        return TreeKeyRegressionFactory.getNewKeyRegression(prf, new byte[16], depth, 2);
    }

    public static SeedNode getSeedNode(int bitLen, long nodeNr, byte[] seed) {
        return new TreeKeyRegressionNode(seed, bitLen, nodeNr);
    }

}
