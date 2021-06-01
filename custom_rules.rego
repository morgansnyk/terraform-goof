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
	port := 22
	sg := input.resource.aws_security_group[name]
	sg.ingress[_].to_port == port
	sg.ingress[_].cidr_blocks == ["0.0.0.0/0"]

msg:= {
		"id": "124",
		"publicId": "CUSTOM-124",
		"title": sprintf("Security Group allows for access to port %d", [port]),
		"type": "custom",
		"subType": "EC2",
		"severity": "critical",
		"policyEngineType": "opa",
		"issue": sprintf("Security Group allows for access to port %d", [port]),
		"impact": "Deployment will be blocked until this is resolved.",
		"resolve": "Configure security rule",
		"msg": sprintf("input.resource.aws_vpc.[%s]", [name]),
		"references": "test",
	}

}