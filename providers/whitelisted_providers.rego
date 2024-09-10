package providers

whitelisted_provider_sources := {
	"hashicorp/aws",
	"integrations/github",
}

# check list of required providers
deny[msg] {
	provider_source := input.terraform.required_providers[provider_name].source
	not whitelisted_provider_sources[provider_source]
	msg := sprintf("provider `%v` from `%v` found", [provider_name, provider_source])
}

# Required provider definition is not mandatory.
# Hence, also checking resource and data source prefix against whitelist

not_whitelisted(resource_type) {
	count({provider |
		whitelisted_provider_sources[provider]
		provider_prefix = split(provider, "/")[1]
		startswith(resource_type, provider_prefix)
	}) == 0
}

deny[msg] {
	input.data[_][resource_type][resource_label]
	not_whitelisted(resource_type)
	msg := sprintf("data source `%v.%v` found", [resource_type, resource_label])
}

deny[msg] {
	input.resource[_][resource_type][resource_label]
	not_whitelisted(resource_type)
	msg := sprintf("resource `%v.%v` found", [resource_type, resource_label])
}
