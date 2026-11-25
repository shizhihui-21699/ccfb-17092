// Package risk decides which RPCs are dangerous to call, using only text
// available without calling them: service and method names, and input message
// field names from a descriptor when one is known.
//
// The classifier is intentionally opinionated but auditable: every verdict
// carries the reasons that produced it, so an operator can see why a method
// was treated as mutating and override the decision.
//
// It errs toward *over*-flagging. A false "mutating" verdict costs an
// operator a glance; a false "read-only" verdict costs a production incident.
package risk

import (
	"regexp"
	"strings"

	"grpcscope/internal/model"
)

// tokenSplit breaks CamelCase, snake_case, kebab-case and dotted names into
// lower-cased tokens.
var tokenSplit = regexp.MustCompile(`[A-Z]+[a-z0-9]*|[a-z0-9]+|[A-Z]+`)

func Tokens(s string) []string {
	if s == "" {
		return nil
	}
	raw := tokenSplit.FindAllString(s, -1)
	out := make([]string, 0, len(raw))
	for _, t := range raw {
		out = append(out, strings.ToLower(t))
	}
	return out
}

// destructiveVerbs are tokens that indicate removal or destruction of state.
var destructiveVerbs = map[string]int{
	"delete": 40, "deleteall": 50, "drop": 40, "destroy": 45, "purge": 45,
	"flush": 40, "truncate": 45, "wipe": 45, "clear": 30, "reset": 35,
	"erase": 40, "remove": 30, "revoke": 35, "cancel": 25, "kill": 45,
	"shutdown": 50, "shutdownall": 50, "poweroff": 50, "reboot": 45,
	"restart": 35, "terminate": 40, "evict": 30, "expire": 25, "invalidate": 30,
	"disable": 30, "unregister": 30, "unbind": 25, "detach": 20, "deregister": 30,
	"failover": 35, "rollback": 30, "discard": 35,
}

// mutatingVerbs are tokens that indicate writing or changing state.
var mutatingVerbs = map[string]int{
	"create": 20, "add": 20, "insert": 20, "set": 22, "update": 25, "upsert": 25,
	"put": 18, "post": 12, "write": 22, "putmany": 20, "modify": 25, "edit": 22,
	"patch": 22, "apply": 22, "import": 25, "upload": 25, "save": 20, "store": 18,
	"merge": 20, "replace": 25, "rename": 22, "move": 15, "copy": 12, "clone": 18,
	"restore": 25, "recover": 25, "replay": 25, "reprocess": 25, "rerun": 22,
	"retry": 12, "resend": 12, "resume": 15, "suspend": 25, "pause": 20,
	"start": 18, "stop": 20, "run": 18, "execute": 22, "exec": 22, "invoke": 18,
	"trigger": 20, "schedule": 18, "send": 15, "publish": 18, "emit": 15,
	"push": 15, "notify": 15, "submit": 18, "commit": 20, "approve": 25,
	"reject": 22, "grant": 30, "assign": 20, "bind": 20, "attach": 15,
	"enable": 25, "activate": 25, "register": 18, "sync": 18, "refresh": 18,
	"reload": 22, "reindex": 25, "rebuild": 25, "recalculate": 20, "migrate": 30,
	"rollout": 25, "deploy": 30, "provision": 25, "deprovision": 25, "scale": 20,
	"resize": 18, "rebalance": 22, "compact": 20, "vacuum": 20, "snapshot": 15,
	"backup": 15, "dump": 15, "export": 12, "generate": 15, "rotate": 25,
	"increment": 15, "decrement": 15, "mark": 12, "verify": 10, "confirm": 15,
	"acknowledge": 10, "ack": 10, "handle": 8, "process": 10, "consume": 10,
	"broadcast": 18, "fanout": 18, "forward": 15, "proxy": 12, "relay": 12,
	"simulate": 10, "demo": 8, "seed": 20, "init": 18, "initialize": 18,
	"bootstrap": 22, "setup": 20, "teardown": 30,
}

// readOnlyVerbs indicate retrieval. They reduce suspicion but do not prove
// safety: "GetSecret" still reads a secret.
var readOnlyVerbs = map[string]int{
	"get": 0, "list": 0, "find": 0, "query": 0, "search": 0, "lookup": 0,
	"describe": 0, "show": 0, "view": 0, "read": 0, "fetch": 0, "load": 0,
	"resolve": 0, "exists": 0, "check": 0, "has": 0, "count": 0, "stat": 0,
	"status": 0, "info": 0, "version": 0, "ping": 0, "health": 0, "echo": 0,
	"hello": 0, "whoami": 0, "debug": 0, "inspect": 0, "scan": 0, "watch": 0,
	"stream": 0, "subscribe": 0, "monitor": 0, "measure": 0, "estimate": 0,
	"preview": 0, "validate": 0, "lint": 0, "analyze": 0, "explain": 0,
	"diff": 0, "compare": 0, "parse": 0, "convert": 0, "encode": 0, "decode": 0,
}

// adminishServiceTokens mark a service as management-facing.
var adminishServiceTokens = map[string]bool{
	"admin": true, "management": true, "manage": true, "ops": true, "operation": true,
	"operator": true, "internal": true, "debug": true, "diagnostic": true,
	"maintenance": true, "control": true, "config": true, "configuration": true,
	"meta": true, "system": true, "sys": true, "root": true, "superuser": true,
	"privileged": true, "private": true, "backend": true, "infra": true,
	"cluster": true, "node": true, "shard": true, "replica": true, "master": true,
	"orchestrator": true, "controller": true, "agent": true, "executor": true,
	"console": true, "shell": true, "cmd": true, "command": true,
}

// sensitiveFieldSet holds tokens that make a *read* dangerous: credentials,
// secrets, and personal data. A bare "key" is deliberately excluded because it
// is overwhelmingly a map key or resource identifier in real schemas; only
// "apikey"/"privatekey" and the credential words themselves count.
var sensitiveFieldSet = map[string]bool{
	"password": true, "passwd": true, "secret": true, "token": true,
	"credential": true, "credentials": true, "authorization": true,
	"apikey": true, "api_key": true, "privatekey": true, "private_key": true,
	"secretkey": true, "secret_key": true, "certificate": true, "cert": true,
	"signature": true, "salt": true, "nonce": true, "otp": true, "mfa": true,
	"ssn": true, "email": true, "phone": true, "card": true, "cvv": true,
	"pin": true, "dob": true, "birth": true,
}

// Classify returns the risk verdict for one method. inputFields may be nil.
func Classify(serviceName, methodName string, inputFields []model.FieldInfo) model.Risk {
	svcTokens := Tokens(serviceName)
	mTokens := Tokens(methodName)

	r := model.Risk{Level: model.RiskUnknown}

	adminish := false
	for _, svcTok := range svcTokens {
		if adminishServiceTokens[svcTok] {
			adminish = true
			break
		}
	}
	// A service segment that is literally "admin" in any casing is a strong
	// signal even when it appears as a package segment (admin.v1.Users).
	r.Adminish = adminish

	eq := func(tokens []string) (hit string, score int) {
		for _, t := range tokens {
			if v, ok := destructiveVerbs[t]; ok {
				return t, v
			}
		}
		for _, t := range tokens {
			if v, ok := mutatingVerbs[t]; ok {
				return t, v
			}
		}
		return "", 0
	}

	// The verb comes from the method name only. Service names contribute the
	// administrative-flavour signal below; treating service tokens as verbs
	// would let a package name like "demo" or "api" dominate the verdict.
	verb, score := eq(mTokens)

	if verb != "" {
		if isDestructive(verb) {
			r.Level = model.RiskDestructive
		} else {
			r.Level = model.RiskMutating
		}
		r.Score = score
		r.Reasons = append(r.Reasons, "verb "+quote(verb)+" indicates state change")
	} else if onlyReadOnly(mTokens) {
		r.Level = model.RiskReadOnly
	} else {
		r.Level = model.RiskUnknown
	}

	if r.Adminish {
		r.Score += 15
		r.Reasons = append(r.Reasons, "service name indicates an administrative or internal API")
	}

	// Input fields that carry credentials or personal data raise the score,
	// and if the method was "unknown" they can pull it up to mutating.
	sensitive := 0
	for _, f := range inputFields {
		for _, t := range Tokens(f.Name) {
			if sensitiveFieldSet[t] {
				sensitive++
				break
			}
		}
	}
	if sensitive > 0 {
		r.Score += 10 * min(sensitive, 3)
		r.Reasons = append(r.Reasons, "input carries sensitive-sounding field(s)")
		if r.Level == model.RiskUnknown {
			r.Level = model.RiskMutating
		}
	}

	// Known read-only names cannot be pulled up by sensitivity alone unless the
	// input is carrying credentials, which is exactly the case where a read is
	// dangerous.
	if r.Level == model.RiskReadOnly && sensitive > 0 {
		r.Level = model.RiskMutating
		r.Reasons = append(r.Reasons, "read-only verb but credential-bearing input")
	}

	if len(r.Reasons) == 0 {
		r.Reasons = append(r.Reasons, "name carries no recognizable action verb")
	}
	return r
}

func isDestructive(verb string) bool {
	_, ok := destructiveVerbs[verb]
	return ok
}

func onlyReadOnly(tokens []string) bool {
	if len(tokens) == 0 {
		return false
	}
	// The first token is the verb position in Go convention; extra tokens are
	// qualifiers. Accept when first or any token is read-only *and* no token
	// mutates.
	for _, t := range tokens {
		if _, ok := destructiveVerbs[t]; ok {
			return false
		}
		if _, ok := mutatingVerbs[t]; ok {
			return false
		}
	}
	// Only the leading token may be the verb. A noun in second position, like
	// the "status" in GetStatus or the "users" in ListUsers, must not be read
	// as an action.
	if _, ok := readOnlyVerbs[tokens[0]]; ok {
		return true
	}
	return false
}

// ServiceRisk is the aggregate risk for a service, used for the report's
// ordering and for the "admin service" surface finding.
func ServiceRisk(name string) model.Risk {
	tokens := Tokens(name)
	adminish := false
	for _, t := range tokens {
		if adminishServiceTokens[t] {
			adminish = true
		}
	}
	r := model.Risk{Level: model.RiskUnknown, Adminish: adminish}
	if adminish {
		r.Reasons = append(r.Reasons, "service name indicates administrative or internal surface")
	}
	return r
}

func quote(s string) string { return `"` + s + `"` }

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// BodyProbeSafe is the gate the scanner consults before sending any request
// body into a method. It is deliberately stricter than Classify: a read-only
// *method* name is not enough if the service it lives on is an administrative
// one. "AdminService/WatchAdmin" reads as read-only by verb but is an
// administrative operation, and an admin-named service means every one of its
// methods must be treated as dangerous until proven otherwise.
//
// A false negative here costs coverage the operator can see in the report; a
// false positive calls something that mutates production.
func BodyProbeSafe(serviceName, methodName string) bool {
	if ServiceRisk(serviceName).Adminish {
		return false
	}
	// Method-level verdict must be read-only, computed without input fields so a
	// credential-bearing input cannot promote it after the fact.
	r := Classify(serviceName, methodName, nil)
	return r.Level == model.RiskReadOnly
}
