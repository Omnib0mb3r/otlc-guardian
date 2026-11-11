/**
 * ============================================================
 * OTLC GUARDIAN - Claude Code settings, read as Claude Code reads them
 * // security · onthelevelconcepts.com
 * Version: 1.5.0
 * ============================================================
 *
 * One reading of .claude/settings.json and settings.local.json for the
 * three places that judge them: `guardian check` (bin/guardian.js) and
 * audit rule AGT-003 (03-audit.js) after the fact, and the PreToolUse
 * hook before a change lands (staged; it imports this file the way it
 * imports the scanner, and guards it as one of Guardian's own files).
 *
 * No dependencies, no side effects on import.
 * ============================================================
 */

/** Guardian's two hooks: the event and a tool its matcher must cover. */
export const REQUIRED_HOOK_REGISTRATIONS = [
  { event: "PreToolUse",  tool: "Write",    file: "injection-guard-hook.mjs" },
  { event: "PostToolUse", tool: "WebFetch", file: "web-content-guard.mjs" },
];

// Claude Code's hooks reference: "*" or an empty matcher matches every
// tool; a matcher of only letters, digits, "_", "-", ",", "|" and spaces
// is a list of exact names split on "|" or ",", spaces around a name
// allowed; anything else is an unanchored JavaScript regex, and an
// invalid one matches nothing. The staged hook reads matchers the same
// way (BUG-045).
export const EXACT_MATCHER = /^[A-Za-z0-9_\-\s,|]*$/;
export function matcherCovers(matcher, tool) {
  const m = typeof matcher === "string" ? matcher.trim() : "";
  if (m === "" || m === "*") return true;
  if (EXACT_MATCHER.test(m)) return m.split(/[|,]/).some((name) => name.trim() === tool);
  try {
    return new RegExp(m).test(tool);
  } catch {
    return false; // an invalid pattern matches no tool
  }
}

/**
 * The required registrations no settings layer meets. A requirement is
 * met when some command hook names the hook file under the event, on a
 * matcher that covers the tool. Layers are the settings objects Claude
 * Code loads; it merges them.
 * @param {object[]} layers - parsed settings objects
 * @param {Array} [required] - defaults to both of Guardian's hooks
 * @returns {string[]} one line per missing registration
 */
export function missingRegistrations(layers, required = REQUIRED_HOOK_REGISTRATIONS) {
  const problems = [];
  for (const req of required) {
    const registered = layers.some((s) => {
      const blocks = Array.isArray(s?.hooks?.[req.event]) ? s.hooks[req.event] : [];
      return blocks.some((b) => matcherCovers(b?.matcher, req.tool) &&
        (Array.isArray(b?.hooks) ? b.hooks : []).some((h) =>
          (h?.type === undefined || h.type === "command") && typeof h?.command === "string" && h.command.includes(req.file)));
    });
    if (!registered) problems.push(`${req.file} is not registered under ${req.event} for ${req.tool}`);
  }
  return problems;
}

// Base types of Claude Code's top-level settings keys, taken from the
// schemastore claude-code-settings schema (2026-11-10). Claude Code loads
// nothing from a settings file in which one of these has another type,
// hooks and permission rules included, and says so only in its startup
// notice (re-probe 3, D2). A key not listed is allowed: Claude Code
// ignores an unknown key. "strings" is an array of strings.
export const SETTINGS_KEY_TYPES = Object.fromEntries(Object.entries({
  boolean: "agentPushNotifEnabled allowAllClaudeAiMcps allowManagedHooksOnly allowManagedMcpServersOnly " +
    "allowManagedPermissionRulesOnly alwaysThinkingEnabled autoCompactEnabled autoConnectIde autoInstallIdeExtension " +
    "autoMemoryEnabled autoScrollEnabled awaySummaryEnabled axScreenReader channelsEnabled disableAgentView " +
    "disableAllHooks disableArtifact disableBrowserExternalNavigation disableBundledSkills disableClaudeAiConnectors " +
    "disableMobileSimulatorTools disableRemoteControl disableSideloadFlags disableSkillShellExecution disableWorkflows " +
    "emojiCompletionEnabled enableAllProjectMcpServers enableArtifact enforceAvailableModels externalEditorContext " +
    "fastMode fastModePerSessionOptIn fileCheckpointingEnabled forceRemoteSettingsRefresh includeCoAuthoredBy " +
    "includeGitInstructions inputNeededNotifEnabled permissionExplainerEnabled prefersReducedMotion " +
    "remoteControlAtStartup requireCoworkFullVmSandbox respectGitignore respondToBashCommands " +
    "showClearContextOnPlanAccept showThinkingSummaries showTurnDuration skipDangerousModePermissionPrompt " +
    "skipWebFetchPreflight spinnerTipsEnabled syntaxHighlightingDisabled terminalProgressBarEnabled " +
    "useAutoModeDuringPlan verbose voiceEnabled wheelScrollAccelerationEnabled workflowKeywordTriggerEnabled " +
    "wslInheritsWindowsSettings",
  string: "$schema advisorModel agent apiKeyHelper askUserQuestionTimeout autoMemoryDirectory autoUpdatesChannel " +
    "awsAuthRefresh awsCredentialExport browserExternalPageTools claudeMd defaultShell diffTool disableAutoMode " +
    "disableDeepLinkRegistration editorMode effortLevel forceLoginGatewayUrl forceLoginMethod gcpAuthRefresh language " +
    "minimumVersion model otelHeadersHelper outputStyle parentSettingsBehavior plansDirectory pluginTrustMessage " +
    "prUrlTemplate preferredNotifChannel processWrapper requiredMaximumVersion requiredMinimumVersion teammateMode " +
    "theme tui viewMode workflowSizeGuideline",
  integer: "cleanupPeriodDays skillListingMaxDescChars",
  number: "feedbackSurveyRate skillListingBudgetFraction",
  object: "attribution autoMode enabledPlugins env extraKnownMarketplaces fileSuggestion hooks modelOverrides " +
    "permissions pluginConfigs policyHelper sandbox skillOverrides spinnerTipsOverride spinnerVerbs statusLine " +
    "subagentStatusLine vimInsertModeRemaps voice worktree",
  strings: "allowedHttpHookUrls availableModels claudeMdExcludes companyAnnouncements disabledMcpjsonServers " +
    "enabledMcpjsonServers fallbackModel httpHookAllowedEnvVars pluginSuggestionMarketplaces skippedMarketplaces " +
    "skippedPlugins sshHostAllowlist",
  array: "allowedChannelPlugins allowedMcpServers blockedMarketplaces deniedMcpServers footerLinksRegexes " +
    "managedMcpServers sshConfigs strictKnownMarketplaces",
  "boolean|strings": "strictPluginOnlyCustomization",
  "string|strings": "forceLoginOrgUUID",
  "null|string": "teammateDefaultModel",
}).flatMap(([types, keys]) => keys.split(" ").map((key) => [key, types.split("|")])));

// The fields inside the settings objects that carry Guardian's standing.
export const SETTINGS_FIELD_TYPES = {
  permissions: { allow: "strings", deny: "strings", ask: "strings", additionalDirectories: "strings",
    defaultMode: "string", disableBypassPermissionsMode: "string", disableAutoMode: "string" },
  statusLine: { type: "string", command: "string", padding: "number", refreshInterval: "integer", hideVimModeIndicator: "boolean" },
};
// Every field of a hook entry, across the command, prompt, agent, http and mcp kinds.
export const HOOK_FIELD_TYPES = { type: "string", command: "string", timeout: "number", async: "boolean", asyncRewake: "boolean",
  shell: "string", if: "string", statusMessage: "string", args: "strings", prompt: "string", model: "string",
  continueOnBlock: "boolean", url: "string", headers: "object", allowedEnvVars: "strings", server: "string",
  tool: "string", input: "object" };

const TYPE_WORDS = { boolean: "a boolean", string: "a string", integer: "an integer", number: "a number", null: "null",
  object: "an object", array: "an array", strings: "an array of strings" };

function jsonTypeIs(value, type) {
  switch (type) {
    case "boolean":
    case "string":  return typeof value === type;
    case "number":  return typeof value === "number" && Number.isFinite(value);
    case "integer": return Number.isInteger(value);
    case "null":    return value === null;
    case "object":  return value !== null && typeof value === "object" && !Array.isArray(value);
    case "array":   return Array.isArray(value);
    case "strings": return Array.isArray(value) && value.every((v) => typeof v === "string");
    default:        return true;
  }
}

function jsonTypeWord(value) {
  if (value === undefined) return "missing";
  if (value === null) return "null";
  if (Array.isArray(value)) return "an array";
  if (Number.isInteger(value)) return "an integer";
  return TYPE_WORDS[typeof value] ?? typeof value;
}

/**
 * Known settings keys whose value has a type Claude Code rejects. Claude
 * Code then loads nothing from the file, hooks included (BUG-073).
 * @param {object} settings - a parsed settings object
 * @returns {string[]} one line per wrong value, naming where it is
 */
export function settingsTypeProblems(settings) {
  const problems = [];
  // A hook event name comes from the file and is echoed into messages a
  // model reads (the PreToolUse hook's prompt), so it is cut short and
  // stripped of anything that could act as markup there.
  const printable = (key) => String(key).replace(/[^\x20-\x7E]/g, "?").replace(/[<>[\]{}`]/g, "").slice(0, 40);
  const check = (where, value, types) => {
    if (types.some((t) => jsonTypeIs(value, t))) return true;
    problems.push(`"${where}" is ${jsonTypeWord(value)} where Claude Code expects ${types.map((t) => TYPE_WORDS[t]).join(" or ")}`);
    return false;
  };
  for (const [key, types] of Object.entries(SETTINGS_KEY_TYPES)) {
    if (Object.hasOwn(settings, key)) check(key, settings[key], types);
  }
  for (const [key, fields] of Object.entries(SETTINGS_FIELD_TYPES)) {
    if (!jsonTypeIs(settings[key], "object")) continue;
    for (const [field, type] of Object.entries(fields)) {
      if (Object.hasOwn(settings[key], field)) check(`${key}.${field}`, settings[key][field], [type]);
    }
  }
  if (!jsonTypeIs(settings.hooks, "object")) return problems;
  for (const [event, blocks] of Object.entries(settings.hooks)) {
    const name = `hooks.${printable(event)}`;
    if (!check(name, blocks, ["array"])) continue;
    blocks.forEach((block, i) => {
      const at = `${name}[${i}]`;
      if (!check(at, block, ["object"])) return;
      if (Object.hasOwn(block, "matcher")) check(`${at}.matcher`, block.matcher, ["string"]);
      if (!check(`${at}.hooks`, block.hooks, ["array"])) return;
      block.hooks.forEach((h, j) => {
        if (!check(`${at}.hooks[${j}]`, h, ["object"])) return;
        for (const [field, type] of Object.entries(HOOK_FIELD_TYPES)) {
          if (Object.hasOwn(h, field)) check(`${at}.hooks[${j}].${field}`, h[field], [type]);
        }
      });
    });
  }
  return problems;
}

/**
 * One settings file as Claude Code loads it: the object, or null with the
 * reasons it loads nothing (not JSON, not an object, a value of the wrong
 * type; Claude Code then drops the whole file, hooks included).
 * @param {string} text - the file's content
 * @param {string} name - how messages name the file, e.g. ".claude/settings.json"
 * @returns {{ settings: object | null, problems: string[] }}
 */
export function loadSettingsText(text, name) {
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch (e) {
    return { settings: null, problems: [`${name} is not valid JSON (${e.message}), so Claude Code registers no hooks from it`] };
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    return { settings: null, problems: [`${name} is not a JSON object, so Claude Code registers no hooks from it`] };
  }
  const wrong = settingsTypeProblems(parsed);
  if (wrong.length === 0) return { settings: parsed, problems: [] };
  return { settings: null, problems: wrong.map((w) => `${name}: ${w}, so Claude Code loads nothing from the file, hooks included`) };
}
