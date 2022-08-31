package collection

import "testing"

const collectionForJava = `[{
        "name": "collectionMedium",
        "policy": "{\"identities\":{\"org1\":{\"role\":{\"name\":\"member\",\"mspId\":\"org1MSP\"}},\"org2\":{\"role\":{\"name\":\"member\",\"mspId\":\"org2MSP\"}}},\"policy\":{\"1-of\":[{\"signed-by\":\"org1\"},{\"signed-by\":\"org2\"}]}}",
        "requiredPeerCount": 0,
        "maxPeerCount": 3,
        "blockToLive": 1000000,
        "memberOnlyRead": true
    },
    {
        "name": "collectionPrivate",
        "policy": "{\"identities\":{\"org1\":{\"role\":{\"name\":\"member\",\"mspId\":\"org1MSP\"}},\"org2\":{\"role\":{\"name\":\"member\",\"mspId\":\"org2MSP\"}}},\"policy\":{\"1-of\":[{\"signed-by\":\"org1\"},{\"signed-by\":\"org2\"}]}}",
        "requiredPeerCount": 0,
        "maxPeerCount": 3,
        "blockToLive": 5,
        "memberOnlyRead": true
    }
]`

const collection = `[{
        "name": "collectionMedium",
        "policy": "OR('Org1MSP.member', 'Org2MSP.member','Org3MSP.member')",
        "requiredPeerCount": 0,
        "maxPeerCount": 3,
        "blockToLive": 1000000,
        "memberOnlyRead": true
    },
    {
        "name": "collectionPrivate",
        "policy": "OR('Org1MSP.member')",
        "requiredPeerCount": 0,
        "maxPeerCount": 3,
        "blockToLive": 5,
        "memberOnlyRead": true
    }
]`

func TestCollection(t *testing.T) {
	collectionConfigFromBytes, _, err := GetCollectionConfigFromBytes([]byte(collection))
	if err != nil {
		t.Error(err)
		return
	}
	t.Log(collectionConfigFromBytes)

	collectionConfigFromBytes, _, err = GetCollectionConfigFromBytesForJava([]byte(collectionForJava))
	if err != nil {
		t.Error(err)
		return
	}
	t.Log(collectionConfigFromBytes)

}
