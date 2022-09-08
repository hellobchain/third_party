package policydsl

import (
	"bytes"
	"github.com/golang/protobuf/proto"
	cb "github.com/hyperledger/fabric-protos-go/common"
	mb "github.com/hyperledger/fabric-protos-go/msp"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
	"strconv"
	"strings"
)

func parseIdentitiesForNode(identities []interface{}) ([]*mb.MSPPrincipal, error) {
	mspPrincipals := make([]*mb.MSPPrincipal, len(identities))
	for i, v := range identities {
		if mspPrincipals[i] != nil {
			return nil, errors.Errorf("In identities with key %v is listed more than once", i)
		}

		vMap, ok := v.(map[interface{}]interface{})
		if !ok {
			return nil, errors.Errorf("In identities with key %v value expected map got %v", i, v)
		}

		roleObj := vMap[Role]
		if roleObj == nil {
			return nil, errors.Errorf("In identities with key %v value must be not nil for role", i)
		}
		roleMap, ok := roleObj.(map[interface{}]interface{})
		if !ok {
			return nil, errors.Errorf("In identities with key %v value expected map for role got %v", i, roleObj)
		}

		nameObj := roleMap[Name]
		if nameObj == nil {
			return nil, errors.Errorf("In identities with key %v name must be not nil in role", i)
		}
		name, ok := nameObj.(string)
		if !ok {
			return nil, errors.Errorf("In identities with key %v name expected string in role got %v", i, nameObj)
		}
		name = strings.TrimSpace(name)

		mspIdObj := roleMap[MspID2]
		if mspIdObj == nil {
			return nil, errors.Errorf("In identities with key %v mspId must be not nil in role", i)
		}
		mspId, ok := mspIdObj.(string)
		if !ok {
			return nil, errors.Errorf("In identities with key %v mspId expected string in role got %v", i, mspIdObj)
		}

		if mspId == "" {
			return nil, errors.Errorf("In identities with key %v mspId must be not empty in role", i)
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
			return nil, errors.Errorf("error marshalling msp role: %s", err)
		}

		mspPrincipals[i] = &mb.MSPPrincipal{
			PrincipalClassification: mb.MSPPrincipal_ROLE,
			Principal:               mspRole,
		}
	}

	if len(mspPrincipals) == 0 {
		return nil, errors.New("No identities were found in the policy specification")
	}
	return mspPrincipals, nil
}

func parsePolicyForNode(identitiesMap []*mb.MSPPrincipal, policy map[string]interface{}) (*cb.SignaturePolicy, error) {
	if policy == nil {
		return nil, errors.New("No policy section was found in the document")
	}
	for k, v := range policy {
		if k == SBy {
			vo, ok := v.(int)
			if !ok {
				return nil, errors.New("signed-by expecting a int value")
			}
			if vo >= len(identitiesMap) {
				return nil, errors.Errorf("No Identities found by index %v in signed-by.", vo)
			}
			mspInfos := identitiesMap[vo]
			if mspInfos == nil {
				return nil, errors.Errorf("No Identities found by index %v in signed-by.", vo)
			}
			return SignedBy(int32(vo)), nil
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
					strLen := len(vStringLists)
					if strLen < matchNo {
						return nil, errors.Errorf("%v expected to have at least %v items to match but only found %v", k, matchNo, strLen)
					}
					sps := make([]*cb.SignaturePolicy, strLen)
					for i, vStringList := range vStringLists {
						nlo, ok := vStringList.(map[interface{}]interface{})
						if !ok {
							return nil, errors.Errorf("expect map[interface]interface got %v", vStringList)
						}
						toMapString, err := mapInterfaceToMapString(nlo)
						if err != nil {
							return nil, err
						}
						signaturePolicy, err := parsePolicyForNode(identitiesMap, toMapString)
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

func PolicyParseNode(yamlString string) (*cb.SignaturePolicyEnvelope, error) {
	newViper := viper.New()
	newViper.SetConfigType("yaml")
	blockReader := bytes.NewBufferString(yamlString)
	defer blockReader.Reset()
	err := newViper.ReadConfig(blockReader)
	if err != nil {
		return nil, err
	}
	identitiesValue := newViper.Get("identities")
	if identitiesValue == nil {
		return nil, errors.New("no find identities")
	}
	identities, ok := identitiesValue.([]interface{})
	if !ok {
		return nil, errors.New("find identities but identities is not []interface{}")
	}
	mspPrincipals, err := parseIdentitiesForNode(identities)
	if err != nil {
		return nil, err
	}

	rule, err := parsePolicyForNode(mspPrincipals, newViper.GetStringMap("policy"))
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
