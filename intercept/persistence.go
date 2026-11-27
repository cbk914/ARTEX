package intercept

import (
	"encoding/json"
	"strings"
)

// PersistenceTools are the platform tools that store something the agents load or
// run later: a custom tool (its code runs on the host in later calls), an MCP server
// (a stdio entry starts its command), a skill file (agents load it as instructions),
// the global company asset scope (which changes asset attribution), or task
// goals/constraints after the initial operator-supplied decomposition.
// A prompt-injected page can make an agent call them, so each call needs operator
// approval. The approval comes from the built-in ask rules seeded in db
// ("[built-in] Persistent change: ..."). If a rule is missing or disabled,
// the persistent change is denied rather than falling through to ordinary rules.
var PersistenceTools = []string{
	"create_custom_tool", "update_custom_tool",
	"create_mcp", "update_mcp",
	"create_skill", "update_skill_file",
	"add_company_scope",
	"set_goals", "set_constraints",
}

// IsPersistenceTool reports whether name is one of PersistenceTools.
func IsPersistenceTool(name string) bool {
	for _, t := range PersistenceTools {
		if t == name {
			return true
		}
	}
	return false
}

// MatchPersistence decides a call of a persistence tool from the loaded rules. Any
// enabled deny rule that matches wins. Otherwise the first matching built-in ask rule
// answers, so the approval needs no other rule. User allow rules are not consulted:
// an allow rule cannot skip the approval. A missing ask rule denies the call.
func (i *Interceptor) MatchPersistence(toolName string, input []byte) (Decision, bool) {
	if !IsPersistenceTool(toolName) {
		return Decision{}, false
	}
	rules, err := i.rules()
	if err != nil {
		return storeUnreadableDecision(), true
	}
	var ask *compiledRule
	for idx := range rules {
		r := rules[idx]
		if !ruleMatches(r, toolName, input) {
			continue
		}
		if r.Action == "deny" {
			return persistenceDecision(r), true
		}
		if ask == nil && r.Action == "ask" && strings.HasPrefix(r.Name, builtinRulePrefix) {
			ask = &rules[idx]
		}
	}
	if ask == nil {
		return Decision{
			RuleName: "[built-in] Persistent change: approval unavailable",
			Action:   "deny",
			Message:  "persistent platform change blocked: operator approval rule is unavailable",
		}, true
	}
	return persistenceDecision(*ask), true
}

func persistenceDecision(r compiledRule) Decision {
	msg := r.Message
	if msg == "" {
		msg = defaultMessage(r.Action, r.Name)
	}
	configJSON, _ := json.Marshal(r.InterceptRule)
	return Decision{
		RuleName: r.Name, ConfigDigest: digestInput(configJSON),
		Action:         r.Action,
		Message:        msg,
		RuleID:         r.ID,
		TimeoutEnabled: r.TimeoutEnabled,
		TimeoutSeconds: r.TimeoutSeconds,
		TimeoutAction:  r.TimeoutAction,
	}
}
