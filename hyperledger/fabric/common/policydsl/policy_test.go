package policydsl

import (
	"github.com/spf13/viper"
	"testing"
)

func TestPolicyByJavaYaml(t *testing.T) {
	a := "1-of"
	t.Log(noofPattern.FindStringSubmatch(a))
	newViper := viper.New()
	newViper.AddConfigPath("test")
	newViper.SetConfigName("endorserpolicy")
	err := newViper.ReadInConfig()
	t.Log(*newViper)
	if err != nil {
		t.Error(err)
		return
	}
	t.Log("policy", newViper.GetStringMap("policy"), "\nidentities", newViper.GetStringMap("identities"))
	identities, _, err := parseIdentitiesForJava(newViper.GetStringMap("identities"))
	if err != nil {
		t.Error(err)
		return
	}

	t.Log("identities:", identities)

	signaturePolicy, err := parsePolicyForJava(identities, newViper.GetStringMap("policy"))
	if err != nil {
		t.Error(err)
		return
	}

	t.Log("policy:", signaturePolicy)
}

const endorserPolicy = `{"identities":{"org1":{"role":{"name":"member","mspId":"org1MSP"}},"org2":{"role":{"name":"member","mspId":"org2MSP"}}},"policy":{"1-of":[{"signed-by":"org1"},{"signed-by":"org2"}]}}`

func TestPolicyByJava(t *testing.T) {
	for i := 0; i < 20; i++ {
		policyParseJava, err := PolicyParseJava(endorserPolicy)
		if err != nil {
			t.Error(err)
			return
		}
		t.Log("endorser policy:", policyParseJava)
	}

}

const endorserPolicyGo = `OR('org1MSP.member','org2MSP.member')`

func TestPolicyByGo(t *testing.T) {
	policyEnvelope, err := FromString(endorserPolicyGo)
	if err != nil {
		t.Error(err)
		return
	}
	t.Log("endorser policy:", policyEnvelope)
}

const endorserPolicyNode = `{"identities":[{"role":{"name":"member","mspId":"peerOrg1"}},{"role":{"name":"member","mspId":"peerOrg2"}}],"policy":{"2-of":[{"signed-by":0},{"1-of":[{"signed-by":0},{"signed-by":1}]}]}}`

func TestPolicyByNode(t *testing.T) {
	for i := 0; i < 20; i++ {
		policyParseNode, err := PolicyParseNode(endorserPolicyNode)
		if err != nil {
			t.Error(err)
			return
		}
		t.Log("endorser policy:", policyParseNode)
	}
}

func TestSortMap(t *testing.T) {
	sorted := map[string]interface{}{
		"org2": 1,
		"org1": 2,
		"org4": 1,
		"org3": 2,
	}

	t.Log(sortMapKeys(sorted))

}
