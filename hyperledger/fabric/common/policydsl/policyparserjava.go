package policydsl

import (
	"bytes"
	"github.com/golang/protobuf/proto"
	cb "github.com/hyperledger/fabric-protos-go/common"
	mb "github.com/hyperledger/fabric-protos-go/msp"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const (
	Name   = "name"
	MspID  = "mspid"
	MspID2 = "mspId"
	Role   = "role"

	SBy = "signed-by"
)

type mspInfo struct {
	mspPrincipal *mb.MSPPrincipal
	mspNum       int32
}

type stringArray []string

func (l stringArray) Len() int {
	return len(l)
}

func (l stringArray) Less(i, j int) bool {
	switch {
	case l[i] > l[j]:
		return false
	case l[i] < l[j]:
		return true
	default:
		return false
	}
}

func (l stringArray) Swap(i, j int) {
	l[i], l[j] = l[j], l[i]
}

func sortMapKeys(sortedMap map[string]interface{}) []string {
	sortKeys := make(stringArray, len(sortedMap))
	var keyIndex int
	for k, _ := range sortedMap {
		sortKeys[keyIndex] = k
		keyIndex++
	}
	sort.Sort(sortKeys)
	return sortKeys
}

func sortMapArray(sortedMapArray []interface{}) ([]interface{}, error) {
	sortKeys := make(stringArray, len(sortedMapArray))
	newMap := make(map[string]interface{})
	for i, sortedMap := range sortedMapArray {
		nlo, ok := sortedMap.(map[interface{}]interface{})
		if !ok {
			return nil, errors.Errorf("expect map[interface]interface got %v", sortedMap)
		}
		toMapString, err := mapInterfaceToMapString(nlo)
		if err != nil {
			return nil, err
		}
		sortKeys[i] = toMapString[SBy].(string)
		newMap[sortKeys[i]] = sortedMap
	}
	sort.Sort(sortKeys)
	ret := make([]interface{}, sortKeys.Len())
	for i, key := range sortKeys {
		ret[i] = newMap[key]
	}
	return ret, nil
}

func parseIdentitiesForJava(identities map[string]interface{}) (map[string]*mspInfo, []*mb.MSPPrincipal, error) {
	sortIdentitiesMapKeys := sortMapKeys(identities)
	ret := make(map[string]*mspInfo)
	mspPrincipals := make([]*mb.MSPPrincipal, len(identities))
	for i, k := range sortIdentitiesMapKeys {
		if ret[k] != nil {
			return nil, nil, errors.Errorf("In identities with key %v is listed more than once", k)
		}
		v := identities[k]
		vMap, ok := v.(map[string]interface{})
		if !ok {
			return nil, nil, errors.Errorf("In identities with key %v value expected map got %v", k, v)
		}

		roleObj := vMap[Role]
		if roleObj == nil {
			return nil, nil, errors.Errorf("In identities with key %v value must be not nil for role", k)
		}
		roleMap, ok := roleObj.(map[string]interface{})
		if !ok {
			return nil, nil, errors.Errorf("In identities with key %v value expected map for role got %v", k, roleObj)
		}

		nameObj := roleMap[Name]
		if nameObj == nil {
			return nil, nil, errors.Errorf("In identities with key %v name must be not nil in role", k)
		}
		name, ok := nameObj.(string)
		if !ok {
			return nil, nil, errors.Errorf("In identities with key %v name expected string in role got %v", k, nameObj)
		}
		name = strings.TrimSpace(name)

		mspIdObj := roleMap[MspID]
		if mspIdObj == nil {
			return nil, nil, errors.Errorf("In identities with key %v mspId must be not nil in role", k)
		}
		mspId, ok := mspIdObj.(string)
		if !ok {
			return nil, nil, errors.Errorf("In identities with key %v mspId expected string in role got %v", k, mspIdObj)
		}

		if mspId == "" {
			return nil, nil, errors.Errorf("In identities with key %v mspId must be not empty in role", k)
		}
		var r mb.MSPRole_MSPRoleType
		switch name {
		case RoleClient:
			r = mb.MSPRole_CLIENT
		case RoleMember:
			r = mb.MSPRole_MEMBER
		case RoleAdmin:
			r = mb.MSPRole_ADMIN
		case RolePeer:
			r = mb.MSPRole_PEER
		case RoleOrderer:
			r = mb.MSPRole_ORDERER
		}

		/* build the principal we've been told */
		mspRole, err := proto.Marshal(&mb.MSPRole{MspIdentifier: mspId, Role: r})
		if err != nil {
			return nil, nil, errors.Errorf("error marshalling msp role: %s", err)
		}

		p := &mspInfo{
			mspPrincipal: &mb.MSPPrincipal{
				PrincipalClassification: mb.MSPPrincipal_ROLE,
				Principal:               mspRole,
			},
			mspNum: int32(i),
		}
		mspPrincipals[i] = p.mspPrincipal
		ret[k] = p
	}

	if len(ret) == 0 {
		return nil, nil, errors.New("No identities were found in the policy specification")
	}
	return ret, mspPrincipals, nil
}

func parsePolicyForJava(identitiesMap map[string]*mspInfo, policy map[string]interface{}) (*cb.SignaturePolicy, error) {
	if policy == nil {
		return nil, errors.New("No policy section was found in the document")
	}
	for k, v := range policy {
		if k == SBy {
			vo, ok := v.(string)
			if !ok {
				return nil, errors.New("signed-by expecting a string value")
			}
			mspInfos, ok := identitiesMap[vo]
			if !ok {
				return nil, errors.Errorf("No Identities found by name %v in signed-by.", vo)
			}
			return SignedBy(mspInfos.mspNum), nil
		} else {
			if noofPattern.MatchString(k) {
				subm := noofPattern.FindStringSubmatch(k)
				if len(subm) == 2 {
					matchNo, err := strconv.Atoi(subm[1])
					if err != nil {
						return nil, err
					}
					vStringLists, ok := v.([]interface{})
					if !ok {
						return nil, errors.Errorf("%v expected to have array but found %v", k, v)
					}
					mapArray, err := sortMapArray(vStringLists)
					if err != nil {
						return nil, err
					}
					strLen := len(mapArray)
					if strLen < matchNo {
						return nil, errors.Errorf("%v expected to have at least %v items to match but only found %v", k, matchNo, strLen)
					}
					sps := make([]*cb.SignaturePolicy, strLen)
					for i, vStringList := range mapArray {
						nlo, ok := vStringList.(map[interface{}]interface{})
						if !ok {
							return nil, errors.Errorf("expect map[interface]interface got %v", vStringList)
						}
						toMapString, err := mapInterfaceToMapString(nlo)
						if err != nil {
							return nil, err
						}
						signaturePolicy, err := parsePolicyForJava(identitiesMap, toMapString)
						if err != nil {
							return nil, err
						}
						sps[i] = signaturePolicy
					}
					return NOutOf(int32(matchNo), sps), nil
				}
			} else {
				return nil, errors.Errorf("Unsupported policy type %v", k)
			}
		}
	}
	return nil, errors.New("No values found for policy")
}

func mapInterfaceToMapString(mapInterface map[interface{}]interface{}) (map[string]interface{}, error) {
	mapString := make(map[string]interface{})
	for k, v := range mapInterface {
		key, ok := k.(string)
		if !ok {
			return nil, errors.Errorf("expecting a string value got %v", k)
		}
		mapString[key] = v
	}
	return mapString, nil
}

var noofPattern = regexp.MustCompile("^(\\d+)-of$")

func PolicyParseJava(yamlString string) (*cb.SignaturePolicyEnvelope, error) {
	newViper := viper.New()
	newViper.SetConfigType("yaml")
	blockReader := bytes.NewBufferString(yamlString)
	defer blockReader.Reset()
	err := newViper.ReadConfig(blockReader)
	if err != nil {
		return nil, err
	}
	identities, mspPrincipals, err := parseIdentitiesForJava(newViper.GetStringMap("identities"))
	if err != nil {
		return nil, err
	}

	rule, err := parsePolicyForJava(identities, newViper.GetStringMap("policy"))
	if err != nil {
		return nil, err
	}

	p := &cb.SignaturePolicyEnvelope{
		Identities: mspPrincipals,
		Version:    0,
		Rule:       rule,
	}

	return p, nil

}
