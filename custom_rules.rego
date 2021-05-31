package main

deny[msg] {
	resource := input.resource.aws_s3_bucket[name]
	not resource.tags.Team

	msg := {
		"id": "123",
		"publicId": "CUSTOM-123",
		"title": "Missing a tag for owning team",
		"type": "custom",
		"subType": "S3",
		"severity": "critical",
		"policyEngineType": "opa",
		"issue": "There is no defined tag for the owning team",
		"impact": "Deployment will be blocked until this is resolved.",
		"resolve": "Set `aws_s3_bucket.tags.Team`",
		"msg": sprintf("input.resource.aws_s3_bucket[%s].tags", [name]),
		"references": [],
	}

}



deny[msg] {
	sg := input.resource.aws_security_group[_]
	sg.ingress[_].to_port == 5432
	sg.ingress[_].cidr_blocks == ["0.0.0.0/0"]

msg:= {
		"id": "124",
		"publicId": "CUSTOM-124",
		"title": "Security Group allows for access to port 5432",
		"type": "custom",
		"subType": "EC2",
		"severity": "critical",
		"policyEngineType": "opa",
		"issue": "Security Group allows for access to port 5432",
		"impact": "Deployment will be blocked until this is resolved.",
		"resolve": "Define security group",
		"msg": sprintf("input.resource.aws_vpc.[%s]", [sg.name]),
		"references": "test",
	}

}