package policydsl

import (
	"bytes"
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
	newViper := viper.New()
	newViper.SetConfigType("yaml")
	blockReader := bytes.NewBufferString(endorserPolicy)
	defer blockReader.Reset()
	err := newViper.ReadConfig(blockReader)
	if err != nil {
		t.Error("ReadConfig", err)
		return
	}
	t.Log(*newViper)
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
	policyParseJava, err := PolicyParseJava(endorserPolicy)
	if err != nil {
		t.Error(err)
		return
	}
	t.Log("endorser policy:", policyParseJava)

	policyEnvelope, err := FromString(endorserPolicyGo)
	if err != nil {
		t.Error(err)
		return
	}
	t.Log("endorser policy:", policyEnvelope)
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

const endorserPolicyNode = `{"identities":[{"role":{"name":"member","mspId":"peerOrg1"}}],"policy":{"2-of":[{"signed-by":0},{"1-of":[{"signed-by":0},{"signed-by":0}]}]}}`

func TestPolicyByNode(t *testing.T) {
	newViper := viper.New()
	newViper.SetConfigType("yaml")
	blockReader := bytes.NewBufferString(endorserPolicyNode)
	defer blockReader.Reset()
	err := newViper.ReadConfig(blockReader)
	if err != nil {
		t.Error("ReadConfig", err)
		return
	}
	t.Log(newViper.Get("identities"))
	t.Log(newViper.GetStringMap("policy"))

	policyParseNode, err := PolicyParseNode(endorserPolicyNode)
	if err != nil {
		t.Error(err)
		return
	}
	t.Log("endorser policy:", policyParseNode)
}
