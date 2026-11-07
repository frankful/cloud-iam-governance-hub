package model

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestAbstractPermissionJSON(t *testing.T) {
	input := AbstractPermission{
		Principal: PermissionPrincipal{
			Name: "reporting",
			Type: "ServiceIdentity",
		},
		Permissions: []PermissionGrant{
			{
				Action:   ActionStorageRead,
				Resource: "storage://reports",
				Conditions: map[string]interface{}{
					"region": "us-east-1",
				},
			},
		},
		Description: "Read reports",
	}

	data, err := json.Marshal(input)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	var output AbstractPermission
	if err := json.Unmarshal(data, &output); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if !reflect.DeepEqual(output, input) {
		t.Fatalf("JSON round trip = %#v, want %#v", output, input)
	}
}

func TestAbstractActionAWSMap(t *testing.T) {
	tests := []struct {
		action string
		want   []string
	}{
		{ActionStorageRead, []string{"s3:GetObject", "s3:ListBucket"}},
		{ActionStorageWrite, []string{"s3:PutObject", "s3:DeleteObject"}},
		{ActionEC2Read, []string{"ec2:DescribeInstances"}},
	}

	for _, test := range tests {
		t.Run(test.action, func(t *testing.T) {
			if got := AbstractActionAWSMap[test.action]; !reflect.DeepEqual(got, test.want) {
				t.Fatalf("mapping = %v, want %v", got, test.want)
			}
		})
	}
}
