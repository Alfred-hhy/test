package com.example.dataapi.crypto.dualKeyRegression;

import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import com.example.dataapi.crypto.prf.IPRF;

public class HashKeyRegression implements IHashKeyRegression{

    Boolean isOwner =false;

    public ArrayList<TimeNode> hash1;

    public ArrayList<TimeNode> hash2;

    public long length;

    private byte[] seed1;  //03.14 设定是256位

    private byte[] seed2;

    private IPRF prf;

    public HashKeyRegression(Boolean owner,IPRF prf,byte[] seed1,byte[] seed2,long length){

        this.isOwner=owner;
        this.prf=prf;
        this.seed1=seed1;
        this.seed2=seed2;
        this.hash1.add(new HashKeyRegressionNode(seed1,0));
        this.hash2.add(new HashKeyRegressionNode(seed2,length-1));
        for(int i=1;i<length;i++){
            hash1.add(computeNextNode1((HashKeyRegressionNode) hash1.get(i-1)));
            hash2.add(computeNextNode2((HashKeyRegressionNode)hash2.get((int) (length-1-i))));
        }

    }

    private byte[] computehash(byte[] nodeseed){

        byte[] result = new byte[256];

        try {
            // 创建 SHA-256 消息摘要对象
            MessageDigest digest = MessageDigest.getInstance("SHA-256");

            // 计算哈希值
            result = digest.digest(nodeseed);
        } catch (NoSuchAlgorithmException e) {
            System.err.println("SHA-256 algorithm not available");
        }

        return result;
    }

    private HashKeyRegressionNode computeNextNode1(HashKeyRegressionNode hn){

        byte[] result=computehash(hn.getNodeSeed());
        long id=hn.getNodeId()+1;
        return new HashKeyRegressionNode(result,id);
    }

    private HashKeyRegressionNode computeNextNode2(HashKeyRegressionNode hn){

        byte[] result=computehash(hn.getNodeSeed());
        long id=hn.getNodeId()-1;
        return new HashKeyRegressionNode(result,id);
    }

    @Override  //kdf 生成令牌是byte数组？  sha256
    public byte[] getKey(long id) {
        byte[] nodeSeed1 =getNodeSeed1(id);
        byte[] nodeSeed2 =getNodeSeed2(id);
        byte[] mergedArray = new byte[nodeSeed1.length + nodeSeed2.length];
        System.arraycopy(nodeSeed1, 0, mergedArray, 0, nodeSeed1.length);
        System.arraycopy(nodeSeed2, 0, mergedArray, nodeSeed1.length, nodeSeed2.length);

        byte[] salt = {1, 2, 3, 4, 5, 6, 7, 8}; // 随机生成盐值 一起发送
        int keyLength = 32; // 密钥长度
        byte[] derivedKey=new byte[256];
        try {
            SecretKeySpec secretKeySpec = new SecretKeySpec(mergedArray, "HmacSHA256");
            Mac hmacSha256 = Mac.getInstance("HmacSHA256");
            hmacSha256.init(secretKeySpec);

            derivedKey = hmacSha256.doFinal(salt);

            // 输出生成的密钥
            //System.out.println("Generated Key: " + bytesToHex(derivedKey));
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            e.printStackTrace();
        }
        return derivedKey;
    }

    @Override
    public byte[] getNodeSeed1(long id) {

        if(hash1.size()>=id){
            return hash1.get((int) id).getNodeSeed();
        }
        long cur=0;
        byte[] hn=seed1;
        while (cur<id){
            hn=computehash(hn);
            cur++;
        }
        return hn;
    }

    @Override
    public byte[] getNodeSeed2(long id) {
        if(hash2.size()>=id){
            return hash2.get((int) id).getNodeSeed();
        }
        long cur=0;
        byte[] hn=seed2;
        while (cur>id){
            hn=computehash(hn);
            cur--;
        }
        return hn;
    }

    @Override
    public IPRF getPRF() {
        return this.prf;
    }
}
