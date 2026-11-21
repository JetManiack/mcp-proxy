package web

import _ "embed"

//go:embed templates/base.html
var baseTmpl string

//go:embed templates/list_upstreams.html
var listUpstreamsTmpl string

//go:embed templates/new_upstream.html
var newUpstreamTmpl string

//go:embed templates/view_upstream.html
var viewUpstreamTmpl string

//go:embed templates/list_agent_keys.html
var listTokensTmpl string

//go:embed templates/agent_key_created.html
var createdTokenTmpl string
