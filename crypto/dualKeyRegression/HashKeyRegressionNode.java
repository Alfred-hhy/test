package com.example.dataapi.crypto.dualKeyRegression;

public class HashKeyRegressionNode implements TimeNode{

    private  long nodeId;

    private byte[] nodeSeed;

    public HashKeyRegressionNode(byte[] nodeSeed, long nodeId){
        this.nodeSeed=nodeSeed;
        this.nodeId=nodeId;
    }
    @Override
    public long getNodeId() {
        return this.nodeId;
    }

    @Override
    public byte[] getNodeSeed() {
        return this.nodeSeed;
    }

    public void printNode(){
        System.out.println("[hashSeed: "+nodeSeed.toString()+"nodeID: "+nodeId+"]");
    }

    public boolean equals(Object obj){
        if(!(obj instanceof HashKeyRegressionNode)) return false;
        HashKeyRegressionNode hn=(HashKeyRegressionNode) obj;
        return this.nodeId==hn.nodeId && this.nodeSeed==hn.nodeSeed;
    }
}
